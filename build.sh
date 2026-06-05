#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dist_dir=${ENVD_DIST_DIR:-"$repo_dir/build/dist"}
go_image=${ENVD_GO_IMAGE:-"golang:1.22-alpine"}
targets=${ENVD_TARGETS:-"darwin/arm64 darwin/amd64 linux/arm64 linux/amd64"}

mkdir -p "$dist_dir"

build_target() {
  goos=$1
  goarch=$2
  out="$dist_dir/envd-${goos}-${goarch}"
  if [ "$goos" = "windows" ]; then
    out="$out.exe"
  fi

  echo "building $goos/$goarch -> $out"
  if command -v go >/dev/null 2>&1; then
    (cd "$repo_dir" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -o "$out" ./cmd/envd)
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm \
      -v "$repo_dir:/src" \
      -w /src \
      -e CGO_ENABLED=0 \
      -e GOOS="$goos" \
      -e GOARCH="$goarch" \
      "$go_image" \
      sh -lc 'PATH=/usr/local/go/bin:$PATH go build -trimpath -o "/src/build/dist/envd-$GOOS-$GOARCH" ./cmd/envd'
  else
    echo "ERROR: build requires either go or docker" >&2
    exit 1
  fi
}

for target in $targets; do
  case "$target" in
    */*) build_target "${target%/*}" "${target#*/}" ;;
    *) echo "ERROR: invalid target $target, expected os/arch" >&2; exit 1 ;;
  esac
done

echo "built envd binaries:"
find "$dist_dir" -maxdepth 1 -type f -name 'envd-*' -print | sort
