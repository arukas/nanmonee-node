#!/bin/sh
set -eu

# Runs the tests that live inside the fixed kernel patches. They are written
# against the patched sing-quic and sing-anytls APIs, so the temporary sing-box
# copy gets the same replace directives as node/go.mod; against the upstream
# modules the tests do not even compile, which is why they must run from here.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348"
WORK="$ROOT/.build/kernel-tests"

"$ROOT/scripts/prepare.sh"
rm -rf "$WORK"
mkdir -p "$ROOT/.build"
cp -a "$ROOT/.cache/sing-box-v1.14.4" "$WORK"

docker run --rm -v "$ROOT:/src" -w /src/.build/kernel-tests \
  -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" \
  sh -c 'go mod edit -replace=github.com/sagernet/sing-quic=/src/.cache/sing-quic-7e0a5869a5f4 -replace=github.com/anytls/sing-anytls=/src/.cache/sing-anytls-130d2e61b889 && go test -race -count=1 -p=2 -tags "with_quic with_utls" ./protocol/vless/ ./protocol/hysteria2/ ./protocol/anytls/ ./protocol/tuic/'

docker run --rm -v "$ROOT:/src" -w /src/.cache/sing-quic-7e0a5869a5f4 \
  -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" \
  go test -race -count=1 -p=2 ./hysteria2/ ./tuic/

docker run --rm -v "$ROOT:/src" -w /src/.cache/sing-anytls-130d2e61b889 \
  -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" \
  go test -race -count=1 -p=2 ./ ./session/
