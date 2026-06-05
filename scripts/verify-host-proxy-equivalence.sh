#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
envd_bin=${ENVD_BIN:-"$HOME/.local/bin/envd"}
alpine_image=${ENVD_ALPINE_IMAGE:-alpine:3.21}
target_url=${ENVD_PROXY_TEST_URL:-https://example.com/}

if [ ! -x "$envd_bin" ]; then
  envd_bin="$repo_dir/build/envd"
fi
if [ ! -x "$envd_bin" ]; then
  echo "envd binary not found; run ./install.sh or set ENVD_BIN" >&2
  exit 1
fi

echo "==> host proxy protocol check"
"$envd_bin" proxy test -target example.com:443 -timeout 15s

echo "==> Linux client proxy protocol check via host.docker.internal"
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e TARGET_URL="$target_url" \
  "$alpine_image" \
  sh -eu -c '
    apk add --no-cache curl busybox-extras >/dev/null

    echo "checking SOCKS TCP"
    nc -z -w 5 host.docker.internal 11080

    echo "checking HTTP proxy TCP"
    nc -z -w 5 host.docker.internal 11081

    echo "checking SOCKS HTTPS"
    curl -fsS --max-time 20 --socks5-hostname host.docker.internal:11080 "$TARGET_URL" >/dev/null

    echo "checking HTTP CONNECT HTTPS"
    curl -fsS --max-time 20 -x http://host.docker.internal:11081 "$TARGET_URL" >/dev/null
  '

echo "Host proxy equivalence OK: host and Linux Docker clients can use SOCKS and HTTP CONNECT"
