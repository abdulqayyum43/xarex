#!/bin/bash
# Run from repo root to regenerate gRPC stubs

# Python (Cloud Brain)
python -m grpc_tools.protoc \
  -I shared/proto \
  --python_out=cloud-brain/proto \
  --grpc_python_out=cloud-brain/proto \
  shared/proto/xarex.proto

# Go (Probe)
protoc \
  -I shared/proto \
  --go_out=probe/grpc/pb \
  --go-grpc_out=probe/grpc/pb \
  shared/proto/xarex.proto

echo "Proto stubs generated."
