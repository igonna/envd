#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
existing_envd=$(command -v envd 2>/dev/null || true)
if [ "${ENVD_INSTALL_DIR:-}" ]; then
  install_dir=$ENVD_INSTALL_DIR
elif [ "$existing_envd" ]; then
  install_dir=$(dirname -- "$existing_envd")
else
  install_dir="$HOME/.local/bin"
fi
build_dir="$repo_dir/build"
out="$build_dir/envd"
go_image=${ENVD_GO_IMAGE:-"golang:1.22-alpine"}
go_cache_dir=${ENVD_GO_CACHE_DIR:-"$build_dir/cache/go"}

find_envd_on_path() {
  found=""
  old_ifs=$IFS
  IFS=:
  for dir in $PATH; do
    [ -n "$dir" ] || continue
    candidate=$dir/envd
    if [ -x "$candidate" ]; then
      case "
$found
" in
        *"
$candidate
"*) ;;
        *) found="${found}${found:+
}$candidate" ;;
      esac
    fi
  done
  IFS=$old_ifs
  printf '%s\n' "$found"
}

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
host_arch=$(uname -m)
case "$host_os" in
  darwin|linux) goos=$host_os ;;
  *) echo "ERROR: unsupported OS: $host_os" >&2; exit 1 ;;
esac
case "$host_arch" in
  arm64|aarch64) goarch=arm64 ;;
  x86_64|amd64) goarch=amd64 ;;
  *) echo "ERROR: unsupported architecture: $host_arch" >&2; exit 1 ;;
esac

mkdir -p "$build_dir" "$install_dir" "$go_cache_dir/mod" "$go_cache_dir/build"

if command -v go >/dev/null 2>&1; then
  echo "building envd with local go for $goos/$goarch"
  (cd "$repo_dir" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -o "$out" ./cmd/envd)
elif command -v docker >/dev/null 2>&1; then
  echo "local go not found; building envd for $goos/$goarch with docker image $go_image"
  docker run --rm \
    -v "$repo_dir:/src" \
    -v "$go_cache_dir/mod:/go/pkg/mod" \
    -v "$go_cache_dir/build:/root/.cache/go-build" \
    -w /src \
    -e CGO_ENABLED=0 \
    -e GOOS="$goos" \
    -e GOARCH="$goarch" \
    -e GOMODCACHE=/go/pkg/mod \
    -e GOCACHE=/root/.cache/go-build \
    "$go_image" \
    sh -lc 'PATH=/usr/local/go/bin:$PATH go build -trimpath -o /src/build/envd ./cmd/envd'
else
  echo "ERROR: install requires either go or docker" >&2
  exit 1
fi

cp "$out" "$install_dir/envd"
chmod 755 "$install_dir/envd"

duplicates=""
for candidate in $(find_envd_on_path); do
  [ "$candidate" = "$install_dir/envd" ] && continue
  duplicates="${duplicates}${duplicates:+
}$candidate"
done

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *)
    echo "envd installed to $install_dir/envd"
    echo "Add this to your shell profile if envd is not found:"
    echo "  export PATH=\"$install_dir:\$PATH\""
    exit 0
    ;;
esac

echo "envd installed to $install_dir/envd"
if [ -n "$duplicates" ]; then
  echo "WARNING: other envd binaries exist later on PATH and may be stale:" >&2
  printf '  %s\n' $duplicates >&2
  echo "Remove them or run with ENVD_INSTALL_DIR set to the intended location." >&2
fi
