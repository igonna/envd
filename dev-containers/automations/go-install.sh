#!/usr/bin/env bash
set -e

VERSION="${GO_VERSION:-go1.26.0}"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${HOST_ARCH}" >&2
    exit 1
    ;;
esac

ARCHIVE="${VERSION}.linux-${GO_ARCH}.tar.gz"
URL="https://go.dev/dl/${ARCHIVE}"

echo "Downloading ${ARCHIVE}..."
curl -fL -o "${ARCHIVE}" "${URL}"

echo "Removing old Go (if exists)..."
sudo rm -rf /usr/local/go

echo "Installing Go..."
sudo tar -C /usr/local -xzf "${ARCHIVE}"
rm -f "${ARCHIVE}"

echo "Linking Go into /usr/local/bin..."
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

echo "Installed:"
go version
