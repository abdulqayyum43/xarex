// Package grpcclient provides the gRPC client wrapper used by the probe to
// communicate with the Xarex Cloud Brain.
package grpcclient

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/xarex/probe/grpc/pb"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	backoffFactor  = 2.0
)

// XarexClient wraps the gRPC connection and the generated service client.
// It manages connection lifecycle including exponential-backoff reconnect.
type XarexClient struct {
	addr   string
	logger *slog.Logger

	mu     sync.Mutex
	conn   *googlegrpc.ClientConn
	client pb.XarexServiceClient
}

// NewXarexClient creates a XarexClient that will connect to addr.
// Call Connect() before using any RPC methods.
func NewXarexClient(addr string, logger *slog.Logger) *XarexClient {
	return &XarexClient{
		addr:   addr,
		logger: logger,
	}
}

// Connect dials the Cloud Brain with exponential backoff.
// It blocks until a connection is established or ctx is cancelled.
func (c *XarexClient) Connect(ctx context.Context) error {
	backoff := initialBackoff

	for attempt := 1; ; attempt++ {
		c.logger.Info("connecting to cloud brain", "addr", c.addr, "attempt", attempt)

		conn, err := googlegrpc.NewClient(
			c.addr,
			googlegrpc.WithTransportCredentials(insecure.NewCredentials()),
			googlegrpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                30 * time.Second, // ping every 30s (was 20s)
				Timeout:             10 * time.Second,
				PermitWithoutStream: true,
			}),
		)
		if err == nil {
			c.mu.Lock()
			c.conn = conn
			c.client = pb.NewXarexServiceClient(conn)
			c.mu.Unlock()
			c.logger.Info("connected to cloud brain", "addr", c.addr)
			return nil
		}

		c.logger.Warn("connection failed, will retry",
			"addr", c.addr,
			"error", err,
			"next_attempt_in", backoff,
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("connect: context cancelled: %w", ctx.Err())
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(float64(backoff)*backoffFactor, float64(maxBackoff)))
	}
}

// Close tears down the underlying gRPC connection.
func (c *XarexClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Register sends ProbeInfo to the Cloud Brain and returns the response.
func (c *XarexClient) Register(ctx context.Context, info *pb.ProbeInfo) (*pb.HeartbeatResponse, error) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()

	resp, err := client.Register(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return resp, nil
}

// Heartbeat sends a periodic liveness ping and returns any pending tasks.
func (c *XarexClient) Heartbeat(ctx context.Context, info *pb.ProbeInfo) (*pb.HeartbeatResponse, error) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()

	resp, err := client.Heartbeat(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	return resp, nil
}

// StartScanStream opens the bidirectional ScanStream and runs it until ctx is
// cancelled or a fatal error occurs. It automatically reconnects on transient
// errors and retries any results that failed to send on the previous stream.
//
//   - resultChan: the caller pushes completed ScanResult values here; this function
//     reads them and sends them upstream to the Cloud Brain.
//   - taskChan: this function writes incoming ScanTask values here for the caller to
//     pick up and dispatch.
func (c *XarexClient) StartScanStream(
	ctx context.Context,
	resultChan <-chan *pb.ScanResult,
	taskChan chan<- *pb.ScanTask,
) {
	// pendingResults buffers results that failed to send so they are retried
	// on the next stream connection — prevents result loss on stream drops.
	pendingResults := make([]*pb.ScanResult, 0, 8)
	backoff := initialBackoff

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("scan stream stopped: context cancelled")
			return
		default:
		}

		unsent, err := c.runStream(ctx, resultChan, taskChan, pendingResults)
		pendingResults = unsent

		if err == nil || err == io.EOF {
			// Clean shutdown.
			return
		}

		c.logger.Warn("scan stream error, reconnecting",
			"error", err,
			"next_attempt_in", backoff,
			"pending_results", len(pendingResults),
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(float64(backoff)*backoffFactor, float64(maxBackoff)))

		// Re-establish the underlying connection before retrying.
		if connErr := c.Connect(ctx); connErr != nil {
			c.logger.Error("reconnect failed", "error", connErr)
			return
		}
		backoff = initialBackoff // reset after successful reconnect
	}
}

// runStream runs one iteration of the bidirectional stream.
// pendingResults are flushed first before reading from resultChan.
// Returns any result that failed to send so it can be retried.
func (c *XarexClient) runStream(
	ctx context.Context,
	resultChan <-chan *pb.ScanResult,
	taskChan chan<- *pb.ScanTask,
	pendingResults []*pb.ScanResult,
) ([]*pb.ScanResult, error) {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()

	stream, err := client.ScanStream(ctx)
	if err != nil {
		return pendingResults, fmt.Errorf("open scan stream: %w", err)
	}

	c.logger.Info("scan stream established")

	// unsentChan carries a result back from the send goroutine if Send fails.
	unsentChan := make(chan *pb.ScanResult, 1)
	sendErr := make(chan error, 1)

	go func() {
		// Flush results from a previous failed stream first.
		for _, result := range pendingResults {
			if err := stream.Send(result); err != nil {
				unsentChan <- result
				sendErr <- fmt.Errorf("send result (retry): %w", err)
				return
			}
			c.logger.Info("retried pending scan result", "task_id", result.TaskId)
		}

		for {
			select {
			case <-ctx.Done():
				_ = stream.CloseSend()
				sendErr <- nil
				return
			case result, ok := <-resultChan:
				if !ok {
					_ = stream.CloseSend()
					sendErr <- nil
					return
				}
				if err := stream.Send(result); err != nil {
					unsentChan <- result
					sendErr <- fmt.Errorf("send result: %w", err)
					return
				}
				c.logger.Debug("sent scan result",
					"task_id", result.TaskId,
					"success", result.Success,
					"findings", len(result.Findings),
				)
			}
		}
	}()

	// Receive tasks from the cloud (runs in the calling goroutine).
	for {
		task, err := stream.Recv()
		if err == io.EOF {
			c.logger.Info("scan stream closed by server")
			return nil, io.EOF
		}
		if err != nil {
			// Collect any unsent result to carry over to the next stream.
			var unsent []*pb.ScanResult
			select {
			case r := <-unsentChan:
				unsent = []*pb.ScanResult{r}
				c.logger.Warn("result not delivered, will retry on reconnect", "task_id", r.TaskId)
			default:
			}
			// Drain send goroutine.
			select {
			case sErr := <-sendErr:
				if sErr != nil {
					c.logger.Warn("send goroutine also errored", "error", sErr)
				}
			default:
			}
			return unsent, fmt.Errorf("recv task: %w", err)
		}

		c.logger.Info("received scan task",
			"task_id", task.TaskId,
			"type", task.Type.String(),
		)

		select {
		case taskChan <- task:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
