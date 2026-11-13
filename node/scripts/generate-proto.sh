#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348"
ZIP="$ROOT/.cache/tools/protoc-33.1-linux-x86_64.zip"
TOOL_DIR="$ROOT/.cache/tools/protoc-33.1"
EXPECTED="f3340e28a83d1c637d8bafdeed92b9f7db6a384c26bca880a6e5217b40a4328b"

mkdir -p "$ROOT/.cache/tools" "$ROOT/.cache/bin"
if [ ! -f "$ZIP" ]; then
  curl -fL --retry 3 https://github.com/protocolbuffers/protobuf/releases/download/v33.1/protoc-33.1-linux-x86_64.zip -o "$ZIP"
fi
ACTUAL=$(shasum -a 256 "$ZIP" | cut -d ' ' -f1)
if [ "$ACTUAL" != "$EXPECTED" ]; then
  printf 'unexpected protoc archive SHA-256: %s\n' "$ACTUAL" >&2
  exit 1
fi
if [ ! -x "$TOOL_DIR/bin/protoc" ]; then
  unzip -q "$ZIP" -d "$TOOL_DIR"
fi
docker run --rm -v "$ROOT:/src" -w /src -e GOBIN=/src/.cache/bin -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build -e GOTOOLCHAIN=local "$IMAGE" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
docker run --rm -v "$ROOT:/src" -w /src -e GOBIN=/src/.cache/bin -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build -e GOTOOLCHAIN=local "$IMAGE" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
docker run --rm -v "$ROOT:/src" -w /src -e PATH=/src/.cache/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "$IMAGE" /src/.cache/tools/protoc-33.1/bin/protoc --proto_path=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/node/v1/node_control.proto
