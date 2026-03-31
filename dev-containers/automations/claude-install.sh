#!/usr/bin/env bash
curl -fsSL https://claude.ai/install.sh | bash

echo
echo "Run:"
echo "claude"
echo
echo "Then run inside claude:"
echo "/login"
echo
echo "Browser will hit error, check console to know which port,"
echo "then run this command outside of container with port which is trying to reach:"
echo "CLAUDE_PORT=44683; ssh -L \$CLAUDE_PORT:localhost:\$CLAUDE_PORT $(whoami)"
echo
