#!/usr/bin/env bash
set -e

VERSION="go1.26.0"
ARCHIVE="${VERSION}.linux-arm64.tar.gz"
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