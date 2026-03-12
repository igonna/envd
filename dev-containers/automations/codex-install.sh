#!/usr/bin/env bash
set -euo pipefail

export NVM_DIR="$HOME/.nvm"

if [ ! -s "$NVM_DIR/nvm.sh" ]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash
fi

# load nvm in this shell
. "$NVM_DIR/nvm.sh"

# install/use Node 20 for this user
nvm install 20
nvm use 20

# install Codex globally for this user, not system-wide
npm install -g @openai/codex

codex --version

echo
echo "Run outside container:"
echo "ssh -L 1455:localhost:1455 $(whoami)"
echo
echo "Run in current shell (activate nvm):"
echo 'export NVM_DIR="$HOME/.nvm"'
echo '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"'
echo 'nvm use 20'
echo
echo "Then run:"
echo "codex login"