#!/usr/bin/env bash

if ! node -v 2>/dev/null | grep -q '^v20'; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

sudo npm install -g @openai/codex

codex --version

echo
echo "Run outside container:"
echo "ssh -L 1455:localhost:1455 $(whoami)"
echo
echo "Then run:"
echo "codex login"