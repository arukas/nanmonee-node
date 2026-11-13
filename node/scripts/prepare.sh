#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/.cache/sing-box-v1.14.4"
QUIC="$ROOT/.cache/sing-quic-7e0a5869a5f4"
ANYTLS="$ROOT/.cache/sing-anytls-130d2e61b889"
PATCHES="$ROOT/../patches/sing-box-v1.14.4"
QUIC_PATCHES="$ROOT/../patches/sing-quic-7e0a5869a5f4"
ANYTLS_PATCHES="$ROOT/../patches/sing-anytls-130d2e61b889"
COMMIT="c005f35300ce76427dc285481ec5695f5b179cd2"
QUIC_COMMIT="7e0a5869a5f49ed0a685143345dfda0448bbc708"
ANYTLS_COMMIT="130d2e61b8895727bfed4942c535e91b246a9603"
EXPECTED_SING_BOX=" M protocol/anytls/inbound.go
 M protocol/hysteria2/inbound.go
 M protocol/tuic/inbound.go
 M protocol/vless/inbound.go
?? protocol/anytls/nanmonee_hot_update_test.go
?? protocol/hysteria2/nanmonee_hot_update_test.go
?? protocol/tuic/nanmonee_hot_update_test.go
?? protocol/vless/nanmonee_hot_update_test.go"
EXPECTED_QUIC=" M hysteria2/service.go
 M hysteria2/service_packet.go
 M tuic/service.go
 M tuic/service_packet.go
?? tuic/service_test.go"
EXPECTED_ANYTLS=" M service.go
 M session/client.go
 M session/session.go
 M session/stream.go
?? service_test.go
?? session/hook_test.go"

normalize_status() {
  git -C "$1" status --porcelain | while IFS= read -r LINE; do
    case "$LINE" in
      " A "*) printf '?? %s\n' "${LINE#???}" ;;
      *) printf '%s\n' "$LINE" ;;
    esac
  done
}

apply_patch() {
  if git -C "$1" apply --check --reverse "$2" >/dev/null 2>&1; then
    return 0
  fi
  git -C "$1" apply --check "$2"
  git -C "$1" apply "$2"
}

# The patched trees are derived caches owned by this script, and an interrupted
# run can leave one half-patched. A plain `git checkout` cannot repair that state
# because the patch-added files are untracked, so a tree whose dirty paths are a
# strict subset of the fixed patch output is reset and repatched here. Anything
# else still fails closed instead of overwriting work this script did not create.
recover_partial() {
  TREE=$1
  LABEL=$2
  EXPECTED=$3
  ACTUAL=$(normalize_status "$TREE")
  [ -z "$ACTUAL" ] && return 0
  [ "$ACTUAL" = "$EXPECTED" ] && return 0
  UNEXPECTED=""
  while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    if ! printf '%s\n' "$EXPECTED" | grep -qxF -- "$LINE"; then
      UNEXPECTED="${UNEXPECTED}${LINE}
"
    fi
  done <<EOF
${ACTUAL}
EOF
  if [ -n "$UNEXPECTED" ]; then
    printf '%s cache has changes this script did not make:\n%s' "$LABEL" "$UNEXPECTED" >&2
    printf 'refusing to overwrite them; reset the derived cache with:\n  git -C %s checkout -- . && git -C %s clean -fdq\n' "$TREE" "$TREE" >&2
    exit 1
  fi
  printf '%s cache is only partially patched, probably from an interrupted run; re-applying the fixed patches\n' "$LABEL" >&2
  git -C "$TREE" checkout -- .
  git -C "$TREE" clean -fdq
}

check_checksums() {
  while read -r EXPECTED FILE; do
    ACTUAL=$(shasum -a 256 "$1/$FILE" | cut -d ' ' -f1)
    if [ "$ACTUAL" != "$EXPECTED" ]; then
      printf 'patched file content differs from the fixed checksum: %s/%s\n' "$1" "$FILE" >&2
      exit 1
    fi
  done < "$2"
}

# sing-box, the pinned kernel release, plus the two tracked hot-update patches.
if [ ! -d "$SOURCE/.git" ]; then
  git clone --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git "$SOURCE"
fi
ACTUAL=$(git -C "$SOURCE" rev-parse HEAD)
if [ "$ACTUAL" != "$COMMIT" ]; then
  printf 'unexpected sing-box commit: %s\n' "$ACTUAL" >&2
  exit 1
fi
if [ "$(normalize_status "$SOURCE")" != "$EXPECTED_SING_BOX" ]; then
  recover_partial "$SOURCE" sing-box "$EXPECTED_SING_BOX"
fi
apply_patch "$SOURCE" "$PATCHES/0001-vless-hot-update.patch"
apply_patch "$SOURCE" "$PATCHES/0002-hysteria2-hot-update.patch"
apply_patch "$SOURCE" "$PATCHES/0003-anytls-hot-update.patch"
apply_patch "$SOURCE" "$PATCHES/0004-tuic-hot-update.patch"
if [ "$(normalize_status "$SOURCE")" != "$EXPECTED_SING_BOX" ]; then
  printf 'sing-box worktree has changes outside the fixed patches; refusing to build it\n' >&2
  exit 1
fi
check_checksums "$SOURCE" "$PATCHES/patched-files.sha256"
git -C "$SOURCE" diff --check

# sing-quic, the QUIC stack behind the Hysteria2 and TUIC inbounds. It is pinned
# by commit instead of by version because the fixes are not part of any release
# yet.
if [ ! -d "$QUIC/.git" ]; then
  git init --quiet "$QUIC"
  git -C "$QUIC" remote add origin https://github.com/sagernet/sing-quic.git
  git -C "$QUIC" fetch --depth 1 origin "$QUIC_COMMIT"
  git -C "$QUIC" checkout --quiet "$QUIC_COMMIT"
fi
ACTUAL=$(git -C "$QUIC" rev-parse HEAD)
if [ "$ACTUAL" != "$QUIC_COMMIT" ]; then
  printf 'unexpected sing-quic commit: %s\n' "$ACTUAL" >&2
  exit 1
fi
if [ "$(normalize_status "$QUIC")" != "$EXPECTED_QUIC" ]; then
  recover_partial "$QUIC" sing-quic "$EXPECTED_QUIC"
fi
apply_patch "$QUIC" "$QUIC_PATCHES/0001-hysteria2-hot-update.patch"
apply_patch "$QUIC" "$QUIC_PATCHES/0002-tuic-hot-update.patch"
if [ "$(normalize_status "$QUIC")" != "$EXPECTED_QUIC" ]; then
  printf 'sing-quic worktree has changes outside the fixed patch; refusing to build it\n' >&2
  exit 1
fi
check_checksums "$QUIC" "$QUIC_PATCHES/patched-files.sha256"
git -C "$QUIC" diff --check

# sing-anytls, the session layer behind the AnyTLS inbound. It is pinned by
# commit because the revocation fix is not part of any release yet.
if [ ! -d "$ANYTLS/.git" ]; then
  git init --quiet "$ANYTLS"
  git -C "$ANYTLS" remote add origin https://github.com/anytls/sing-anytls.git
  git -C "$ANYTLS" fetch --depth 1 origin "$ANYTLS_COMMIT"
  git -C "$ANYTLS" checkout --quiet "$ANYTLS_COMMIT"
fi
ACTUAL=$(git -C "$ANYTLS" rev-parse HEAD)
if [ "$ACTUAL" != "$ANYTLS_COMMIT" ]; then
  printf 'unexpected sing-anytls commit: %s\n' "$ACTUAL" >&2
  exit 1
fi
if [ "$(normalize_status "$ANYTLS")" != "$EXPECTED_ANYTLS" ]; then
  recover_partial "$ANYTLS" sing-anytls "$EXPECTED_ANYTLS"
fi
# Later patches edit lines earlier ones introduced; check the final patch first.
for PATCH in 0001-anytls-hot-update.patch 0002-client-hook-race.patch 0003-session-identity-and-close-hooks.patch; do
  [ -f "$ANYTLS_PATCHES/$PATCH" ] || { printf 'missing AnyTLS patch: %s\n' "$PATCH" >&2; exit 1; }
done
if ! git -C "$ANYTLS" apply --check --reverse "$ANYTLS_PATCHES/0003-session-identity-and-close-hooks.patch" >/dev/null 2>&1; then
  if ! git -C "$ANYTLS" apply --check --reverse "$ANYTLS_PATCHES/0002-client-hook-race.patch" >/dev/null 2>&1; then
    if ! git -C "$ANYTLS" apply --check --reverse "$ANYTLS_PATCHES/0001-anytls-hot-update.patch" >/dev/null 2>&1; then
      apply_patch "$ANYTLS" "$ANYTLS_PATCHES/0001-anytls-hot-update.patch"
    fi
    apply_patch "$ANYTLS" "$ANYTLS_PATCHES/0002-client-hook-race.patch"
  fi
  apply_patch "$ANYTLS" "$ANYTLS_PATCHES/0003-session-identity-and-close-hooks.patch"
fi
if [ "$(normalize_status "$ANYTLS")" != "$EXPECTED_ANYTLS" ]; then
  printf 'sing-anytls worktree has changes outside the fixed patch; refusing to build it\n' >&2
  exit 1
fi
check_checksums "$ANYTLS" "$ANYTLS_PATCHES/patched-files.sha256"
git -C "$ANYTLS" diff --check
