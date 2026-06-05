#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="$repo_dir/build/cross"
go_image=${ENVD_GO_IMAGE:-golang:1.22-alpine}
alpine_image=${ENVD_ALPINE_IMAGE:-alpine:3.21}

verify_go_target() {
  goarch=$1
  platform=$2
  out_dir="$build_dir/linux-$goarch"
  mkdir -p "$out_dir"

  echo "==> go test for linux/$goarch"
  docker run --rm \
    --platform "$platform" \
    -v "$repo_dir:/src" \
    -w /src \
    -e CGO_ENABLED=0 \
    -e GOOS=linux \
    -e GOARCH="$goarch" \
    "$go_image" \
    sh -lc 'PATH=/usr/local/go/bin:$PATH go test ./...'

  echo "==> go build for linux/$goarch"
  docker run --rm \
    --platform "$platform" \
    -v "$repo_dir:/src" \
    -w /src \
    -e CGO_ENABLED=0 \
    -e GOOS=linux \
    -e GOARCH="$goarch" \
    "$go_image" \
    sh -lc 'PATH=/usr/local/go/bin:$PATH go build -trimpath -o "/src/build/cross/linux-$GOARCH/envd" ./cmd/envd'

  echo "==> binary smoke for linux/$goarch"
  docker run --rm \
    --platform "$platform" \
    -v "$repo_dir:/src:ro" \
    -v "$out_dir/envd:/usr/local/bin/envd:ro" \
    -w /src \
    "$alpine_image" \
    sh -lc 'envd version && envd help >/dev/null && envd proxy >/dev/null'
}

verify_image_target() {
  arch_label=$1
  platform=$2

  echo "==> build sshdev image for $platform"
  docker build \
    --platform "$platform" \
    -t "envd-cross-sshdev:$arch_label" \
    "$repo_dir/dev-containers/sshdev"

  echo "==> build net-sidecar image for $platform"
  docker build \
    --platform "$platform" \
    -t "envd-cross-net-sidecar:$arch_label" \
    "$repo_dir/dev-containers/net-sidecar"

  echo "==> build project Docker image for $platform"
  docker build \
    --platform "$platform" \
    -t "envd-cross-project-docker:$arch_label" \
    "$repo_dir/dev-containers/project-docker"
}

verify_go_target amd64 linux/amd64
verify_go_target arm64 linux/arm64
verify_image_target amd64 linux/amd64
verify_image_target arm64 linux/arm64

echo "Cross-platform verification OK: linux/amd64 and linux/arm64"
