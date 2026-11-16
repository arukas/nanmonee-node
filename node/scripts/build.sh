#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348"

"$ROOT/scripts/prepare.sh"
mkdir -p "$ROOT/.build"
docker run --rm -v "$ROOT:/src" -w /src -e GOOS=linux -e GOARCH=amd64 -e GOAMD64=v1 -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" go build -mod=readonly -p=2 -trimpath -buildvcs=false -tags 'with_quic with_utls' -o .build/nanmonee-node ./cmd/nanmonee-node
docker run --rm -v "$ROOT:/src" -w /src -e GOOS=linux -e GOARCH=amd64 -e GOAMD64=v1 -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" go build -mod=readonly -p=2 -trimpath -buildvcs=false -tags 'with_quic with_utls' -o .build/nanmonee-nodectl ./cmd/nanmonee-nodectl
# The updater runs as root on the host, so it is built with the same fixed
# toolchain and flags but imports nothing from the proxy kernels.
docker run --rm -v "$ROOT:/src" -w /src -e GOOS=linux -e GOARCH=amd64 -e GOAMD64=v1 -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" go build -mod=readonly -p=2 -trimpath -buildvcs=false -o .build/nanmonee-node-updater ./cmd/nanmonee-node-updater

# The manifest's source and panel fingerprints drifted by hand in earlier tasks,
# so a release manifest is only accepted when it still matches this checkout.
if [ -n "${NANMONEE_MANIFEST:-}" ]; then
	python3 "$ROOT/scripts/write_manifest.py" --check "$NANMONEE_MANIFEST"
fi
