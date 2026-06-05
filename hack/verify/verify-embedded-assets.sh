#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
envd_bin=${ENVD_BIN:-"$HOME/.local/bin/envd"}
if [ ! -x "$envd_bin" ]; then
  envd_bin="$repo_dir/build/envd"
fi
if [ ! -x "$envd_bin" ]; then
  echo "envd binary not found; run ./install.sh or set ENVD_BIN" >&2
  exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/envd-embedded-assets.XXXXXX")
state_dir="$work_dir/state"
data_dir="$work_dir/data"
run_dir="$work_dir/run"
password="envd-embedded-assets-test"
env_name="embeddedasset"

cleanup() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd_bin" rm "$env_name" --yes >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$run_dir"

echo "==> remove dev image tag to force embedded restore"
if docker image inspect sshdev:24.04 >/dev/null 2>&1; then
  docker image rm sshdev:24.04 >/dev/null
fi

echo "==> run installed envd outside repo checkout"
(
  cd "$run_dir"
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" \
    "$envd_bin" run "$env_name" --network offline >/dev/null
)

echo "==> verify embedded Docker context was materialized"
test -f "$data_dir/assets/contexts/sshdev_24.04/Dockerfile"
grep -q 'FROM ubuntu:24.04' "$data_dir/assets/contexts/sshdev_24.04/Dockerfile"

echo "==> verify image was restored"
docker image inspect sshdev:24.04 >/dev/null

echo "Embedded asset verification OK"
