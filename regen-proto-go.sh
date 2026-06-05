#!/bin/sh
set -e
apk add --no-cache protoc protobuf-dev > /dev/null
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
export PATH=$PATH:/root/go/bin
cd /proto
protoc \
  --go_out=/out --go_opt=paths=source_relative \
  --go-grpc_out=/out --go-grpc_opt=paths=source_relative \
  xarex.proto
ls -la /out/*.pb.go
