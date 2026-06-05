#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_dir=${ENVD_INSTALL_DIR:-"$HOME/.local/bin"}
build_dir="$repo_dir/build"
out="$build_dir/envd"
go_image=${ENVD_GO_IMAGE:-"golang:1.22-alpine"}

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

mkdir -p "$build_dir" "$install_dir"

if command -v go >/dev/null 2>&1; then
  echo "building envd with local go for $goos/$goarch"
  (cd "$repo_dir" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -o "$out" ./cmd/envd)
elif command -v docker >/dev/null 2>&1; then
  echo "local go not found; building envd for $goos/$goarch with docker image $go_image"
  docker run --rm \
    -v "$repo_dir:/src" \
    -w /src \
    -e CGO_ENABLED=0 \
    -e GOOS="$goos" \
    -e GOARCH="$goarch" \
    "$go_image" \
    go build -trimpath -o /src/build/envd ./cmd/envd
else
  echo "ERROR: install requires either go or docker" >&2
  exit 1
fi

cp "$out" "$install_dir/envd"
chmod 755 "$install_dir/envd"

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
