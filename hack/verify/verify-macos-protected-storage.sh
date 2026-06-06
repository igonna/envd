#!/usr/bin/env sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "SKIP: macOS APFS protected storage verifier requires Darwin"
  exit 0
fi

envd_bin=${ENVD_BIN:-/Users/c/.local/bin/envd}
work_dir=$(mktemp -d "$PWD/build/protected-storage.XXXXXX")
state_dir="$work_dir/state"
data_dir="$work_dir/data"
password="envd-protected-storage-test"
env_name="protectedtest"

cleanup() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd_bin" rm "$env_name" --yes >/dev/null 2>&1 || true
  hdiutil info | awk -v prefix="$data_dir/protected" '
    /^image-path[[:space:]]*:/ {
      path=$0
      sub(/^image-path[[:space:]]*:[[:space:]]*/, "", path)
      hit=index(path, prefix) == 1
      next
    }
    /^\/dev\/disk[0-9]+[[:space:]]/ && hit {print $1}
    /^================================================/ {hit=0}
  ' | sort -u | while IFS= read -r dev; do
    hdiutil detach "$dev" >/dev/null 2>&1 || hdiutil detach -force "$dev" >/dev/null 2>&1 || true
  done
  rm -rf "$work_dir"
}

envd() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd_bin" "$@"
}

assert_unmounted() {
  if hdiutil info | grep -q "$data_dir/protected"; then
    hdiutil info | grep "$data_dir/protected" >&2 || true
    echo "FAIL: protected storage is still mounted after $1" >&2
    exit 1
  fi
  echo "OK: protected storage unmounted after $1"
}

assert_encrypted_image() {
  image=$1
  for _ in $(seq 1 20); do
    if hdiutil isencrypted "$image" >/dev/null 2>&1; then
      echo "OK: protected storage image is encrypted"
      return 0
    fi
    sleep 0.5
  done
  hdiutil isencrypted "$image" >&2 || true
  echo "FAIL: protected storage image encryption check failed" >&2
  exit 1
}

trap cleanup EXIT INT TERM

envd start "$env_name" --network offline --storage protected >/tmp/envd-protected-run.out
grep -q "Storage: protected" /tmp/envd-protected-run.out
grep -q "Storage backend: apfs-sparseimage" /tmp/envd-protected-run.out
echo "OK: protected env created"

image_path=$(find "$data_dir/protected" -name storage.sparseimage -print -quit)
if [ -z "$image_path" ]; then
  echo "FAIL: protected storage image not found" >&2
  exit 1
fi

envd shell "$env_name" sh -lc 'echo protected-data > /repo/proof.txt'
envd stop "$env_name" >/dev/null
assert_unmounted "stop"
assert_encrypted_image "$image_path"

envd start "$env_name" >/dev/null
got=$(envd shell "$env_name" sh -lc 'cat /repo/proof.txt')
if [ "$got" != "protected-data" ]; then
  echo "FAIL: protected storage data did not persist: $got" >&2
  exit 1
fi
echo "OK: protected storage persists across stop/start"

envd lock >/dev/null
assert_unmounted "lock"

envd rm "$env_name" --yes >/dev/null
if [ -d "$data_dir/protected" ] && find "$data_dir/protected" -mindepth 1 -print -quit | grep -q .; then
  find "$data_dir/protected" -mindepth 1 -maxdepth 2 -print >&2
  echo "FAIL: env-owned protected storage remained after rm" >&2
  exit 1
fi
echo "OK: rm removed protected storage"

echo "macOS protected APFS storage verification OK"
