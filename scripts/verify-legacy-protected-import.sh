#!/usr/bin/env sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "SKIP: protected legacy import verifier currently requires macOS APFS backend"
  exit 0
fi

envd_bin=${ENVD_BIN:-/Users/c/.local/bin/envd}
work_dir=$(mktemp -d "$PWD/build/legacy-protected.XXXXXX")
state_dir="$work_dir/state"
data_dir="$work_dir/data"
password="envd-legacy-protected-test"
legacy="legacyprotected"

cleanup() {
  ENVD_STATE_DIR="$state_dir" ENVD_DATA_DIR="$data_dir" ENVD_MASTER_PASSWORD="$password" "$envd_bin" rm "$legacy" --yes >/dev/null 2>&1 || true
  docker rm -f "$legacy" "$legacy-net" >/dev/null 2>&1 || true
  docker volume rm "$legacy-home" "$legacy-repo" >/dev/null 2>&1 || true
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

trap cleanup EXIT INT TERM

docker volume create "$legacy-home" >/dev/null
docker volume create "$legacy-repo" >/dev/null
printf 'legacy-home-data\n' | docker run --rm -i -v "$legacy-home:/data" alpine:3.21 sh -lc 'cat > /data/home.txt'
printf 'legacy-repo-data\n' | docker run --rm -i -v "$legacy-repo:/data" alpine:3.21 sh -lc 'cat > /data/repo.txt'
docker run -d \
  --name "$legacy" \
  --label envd.managed=true \
  --label envd.role=dev \
  --label envd.id="$legacy" \
  --label envd.name="$legacy" \
  --label envd.network=offline \
  --network none \
  -v "$legacy-home:/home/$legacy" \
  -v "$legacy-repo:/home/$legacy/repo" \
  sshdev:24.04 >/dev/null

envd migrate adopt --yes >/dev/null
envd migrate protected "$legacy" --yes >/tmp/envd-legacy-protected.out
grep -q 'Storage:  protected' /tmp/envd-legacy-protected.out
grep -q 'original Docker volumes left untouched' /tmp/envd-legacy-protected.out
echo "OK: legacy env imported into protected storage"

legacy_home=$(docker run --rm -v "$legacy-home:/data:ro" alpine:3.21 cat /data/home.txt)
legacy_repo=$(docker run --rm -v "$legacy-repo:/data:ro" alpine:3.21 cat /data/repo.txt)
if [ "$legacy_home" != "legacy-home-data" ] || [ "$legacy_repo" != "legacy-repo-data" ]; then
  echo "FAIL: legacy source volumes were modified" >&2
  exit 1
fi
echo "OK: legacy source volumes preserved"

envd start "$legacy" >/dev/null
home_got=$(envd shell "$legacy" sh -lc 'cat /home/dev/home.txt')
repo_got=$(envd shell "$legacy" sh -lc 'cat /repo/repo.txt')
if [ "$home_got" != "legacy-home-data" ] || [ "$repo_got" != "legacy-repo-data" ]; then
  echo "FAIL: protected import data mismatch: home=$home_got repo=$repo_got" >&2
  exit 1
fi
echo "OK: imported data restored into envd-owned protected env"

envd stop "$legacy" >/dev/null
if hdiutil info | grep -q "$data_dir/protected"; then
  echo "FAIL: protected storage remained attached after stop" >&2
  exit 1
fi
echo "OK: protected import closes storage on stop"

echo "Legacy protected import verification OK"
