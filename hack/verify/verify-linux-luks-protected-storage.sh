#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
go_image=${ENVD_GO_IMAGE:-golang:1.22-alpine}
alpine_image=${ENVD_ALPINE_IMAGE:-alpine:3.21}
build_dir="$repo_dir/build/linux-luks"
mkdir -p "$build_dir"

arch="$(docker run --rm "$alpine_image" uname -m)"
case "$arch" in
  x86_64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *) echo "Unsupported verifier architecture: $arch" >&2; exit 1 ;;
esac

docker run --rm \
  -v "$repo_dir:/src" \
  -w /src \
  -e CGO_ENABLED=0 \
  -e GOOS=linux \
  -e GOARCH="$goarch" \
  "$go_image" \
  sh -lc 'PATH=/usr/local/go/bin:$PATH go build -trimpath -o /src/build/linux-luks/envd ./cmd/envd'

docker run --rm -i --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$repo_dir:/src" \
  -w /src \
  "$alpine_image" \
  sh -se <<'EOF'
apk add --no-cache cryptsetup docker-cli e2fsprogs util-linux tar >/dev/null

work_dir=$(mktemp -d /tmp/envd-linux-luks.XXXXXX)
state_dir="$work_dir/state"
data_dir="$work_dir/data"
password="envd-linux-luks-test"
env_name="lukstest"
envd=/src/build/linux-luks/envd

cleanup() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd" rm "$env_name" --yes >/dev/null 2>&1 || true
  if mount | grep -q "$work_dir"; then
    mount | awk -v prefix="$work_dir" '$0 ~ prefix {print $3}' | sort -r | while IFS= read -r mountpoint; do
      umount "$mountpoint" >/dev/null 2>&1 || true
    done
  fi
  for mapper in /dev/mapper/envd-*; do
    [ -e "$mapper" ] || continue
    cryptsetup close "$(basename "$mapper")" >/dev/null 2>&1 || true
  done
  rm -rf "$work_dir"
}

envd() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd" "$@"
}

trap cleanup EXIT INT TERM

envd run "$env_name" --network offline --storage protected >/tmp/envd-linux-luks-run.out
grep -q "Storage: protected" /tmp/envd-linux-luks-run.out
grep -q "Storage backend: luks2-dmcrypt" /tmp/envd-linux-luks-run.out
echo "OK: Linux LUKS protected env created"

image_path=$(find "$data_dir/protected" -name storage.luks -print -quit)
if [ -z "$image_path" ]; then
  echo "FAIL: LUKS image not found" >&2
  exit 1
fi
cryptsetup isLuks "$image_path"
echo "OK: LUKS2 image is encrypted"

envd shell "$env_name" sh -lc 'echo luks-data > /repo/proof.txt' </dev/null
envd stop "$env_name" >/dev/null
if mount | grep -q "$data_dir/protected"; then
  echo "FAIL: protected LUKS storage still mounted after stop" >&2
  exit 1
fi
if ls /dev/mapper/envd-* >/dev/null 2>&1; then
  echo "FAIL: LUKS mapper still open after stop" >&2
  ls /dev/mapper/envd-* >&2 || true
  exit 1
fi
echo "OK: LUKS storage closed after stop"

envd start "$env_name" >/dev/null
got=$(envd shell "$env_name" sh -lc 'cat /repo/proof.txt' </dev/null)
if [ "$got" != "luks-data" ]; then
  echo "FAIL: LUKS protected data did not persist: $got" >&2
  exit 1
fi
echo "OK: LUKS protected data persists across stop/start"

envd lock >/dev/null
if mount | grep -q "$data_dir/protected" || ls /dev/mapper/envd-* >/dev/null 2>&1; then
  echo "FAIL: LUKS storage remained open after lock" >&2
  exit 1
fi
echo "OK: LUKS storage closed after lock"

envd rm "$env_name" --yes >/dev/null
if [ -d "$data_dir/protected" ] && find "$data_dir/protected" -mindepth 1 -print -quit | grep -q .; then
  echo "FAIL: LUKS protected storage remained after rm" >&2
  exit 1
fi
echo "OK: rm removed LUKS protected storage"

echo "Linux LUKS protected storage verification OK"
EOF
