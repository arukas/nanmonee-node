#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348"

rtk "$ROOT/scripts/prepare.sh"
rtk mkdir -p "$ROOT/.build"
rtk docker run --rm -v "$ROOT:/src" -w /src -e GOOS=linux -e GOARCH=amd64 -e GOAMD64=v1 -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" go build -mod=readonly -p=2 -trimpath -buildvcs=false -tags 'with_quic with_utls' -o .build/nanmonee-node ./cmd/nanmonee-node
rtk docker run --rm -v "$ROOT:/src" -w /src -e GOOS=linux -e GOARCH=amd64 -e GOAMD64=v1 -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOMODCACHE=/src/.cache/gomod -e GOCACHE=/src/.cache/go-build "$IMAGE" go build -mod=readonly -p=2 -trimpath -buildvcs=false -tags 'with_quic with_utls' -o .build/nanmonee-nodectl ./cmd/nanmonee-nodectl

# The manifest's source and panel fingerprints drifted by hand in earlier tasks,
# so a release manifest is only accepted when it still matches this checkout.
if [ -n "${NANMONEE_MANIFEST:-}" ]; then
	rtk python3 "$ROOT/scripts/write_manifest.py" --check "$NANMONEE_MANIFEST"
fi
