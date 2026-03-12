#!/usr/bin/env bash
set -euo pipefail

export NVM_DIR="${XDG_CONFIG_HOME:-$HOME/.nvm}"

if [ ! -s "$NVM_DIR/nvm.sh" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash
fi

# load nvm for this shell
. "$NVM_DIR/nvm.sh"

# install/use Node 20 for this user
nvm install 20
nvm use 20

node -v
npm -v