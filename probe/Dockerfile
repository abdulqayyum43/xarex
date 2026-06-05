# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build
# Uses Alpine + libpcap-dev so gopacket/pcap compiles with CGO.
# The binary is linked statically so Stage 2 needs no libpcap.so at runtime.
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

# Build-time dependencies only
RUN apk add --no-cache \
    git \
    libpcap-dev \
    linux-headers \
    gcc \
    musl-dev

WORKDIR /src

# Cache module downloads before copying full source — speeds up rebuilds
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binary: CGO required for gopacket/pcap; -extldflags=-static embeds
# libpcap so the runtime image carries no shared-library dependency.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w -extldflags=-static" \
    -trimpath \
    -o /phantom-probe \
    ./

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
#
# debian:bookworm-slim instead of alpine because:
#   - net-tools, iputils-ping, nmap-related packages are better supported
#   - glibc compatibility avoids edge cases with some CGO static binaries
#   - security team tooling typically tests on glibc-based images
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Runtime network tools required for probe operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    net-tools \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user — probe runs as this user where possible.
# Use --create-home so nuclei has a writable $HOME for its config + cache dirs.
RUN groupadd --system phantom && useradd --system --gid phantom --create-home --shell /sbin/nologin phantom

# Install libcap2-bin to setcap the binary for CAP_NET_RAW
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# ─── Install upstream nuclei binary (Apache-2.0) and its template library ────
# Nuclei drives the NUCLEI_SCAN task type via probe/scanner/nuclei.go.
# We pin a specific release for reproducibility; bump as part of normal upgrades.
# The template fetch needs network access at build time.
ARG NUCLEI_VERSION=3.3.7
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && apt-get update && apt-get install -y --no-install-recommends unzip git \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ${NUCLEI_TEMPLATES_DIR} \
    && rm -rf ${NUCLEI_TEMPLATES_DIR}/.git \
    && chmod -R a+rX ${NUCLEI_TEMPLATES_DIR} \
    && apt-get purge -y unzip git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/phantom/.config/nuclei /home/phantom/.cache/nuclei \
    && chown -R phantom:phantom /home/phantom

# Copy binary from builder stage
COPY --from=builder /phantom-probe /opt/phantom/phantom-probe

# Grant CAP_NET_RAW and CAP_NET_ADMIN on the binary so the container can
# perform ARP/ICMP scanning without running as root or --privileged.
RUN setcap cap_net_raw,cap_net_admin+eip /opt/phantom/phantom-probe

# Copy default configuration — individual values can be overridden via ENV
COPY phantom.conf /opt/phantom/phantom.conf

# Probe configuration via environment variables.
# ENV values here are defaults — override all of these at runtime.
ENV CLOUD_BRAIN_ADDR="host.docker.internal:50051" \
    ORG_ID="" \
    PROBE_ID="" \
    SCAN_SUBNETS="" \
    LOG_LEVEL="info" \
    GRPC_TLS="false"

WORKDIR /opt/phantom

# Switch to non-root after setcap
USER phantom

ENTRYPOINT ["./phantom-probe"]
