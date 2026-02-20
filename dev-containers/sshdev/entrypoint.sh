#!/usr/bin/env bash
set -euo pipefail

DEV_USER="${DEV_USER:-dev}"
HOME_DIR="/home/${DEV_USER}"
SSH_DIR="${HOME_DIR}/.ssh"
REPO_DIR="${REPO_DIR:-${HOME_DIR}/repo}"
GIT_USER_NAME="${GIT_USER_NAME:-}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-}"

if ! id -u "$DEV_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$DEV_USER"
  echo "${DEV_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${DEV_USER}"
  chmod 440 "/etc/sudoers.d/${DEV_USER}"
fi

mkdir -p "$HOME_DIR"

# If home is a mounted volume, /etc/skel wasn't copied. Copy defaults once.
if [ ! -f "${HOME_DIR}/.bashrc" ] && [ -d /etc/skel ]; then
  # copy skeleton files but don't overwrite anything that already exists
  cp -an /etc/skel/. "$HOME_DIR/" 2>/dev/null || true
fi

# --- ensure repo dir exists and is writable by DEV_USER ---
mkdir -p "$REPO_DIR"
chown -R "${DEV_USER}:${DEV_USER}" "$REPO_DIR" 2>/dev/null || true
chmod 775 "$REPO_DIR" 2>/dev/null || true

# Keep /repo as stable path, but point it to a user-writable parent hierarchy.
if [ ! -e /repo ]; then
  ln -s "$REPO_DIR" /repo
fi

# Ensure colored prompt even if skel was minimal
if ! grep -q "dev-env: ensure colored prompt" "${HOME_DIR}/.bashrc" 2>/dev/null; then
  cat >> "${HOME_DIR}/.bashrc" <<'EOF'

# --- dev-env: ensure colored prompt ---
force_color_prompt=yes
if [ -n "$force_color_prompt" ] && [ -x /usr/bin/tput ] && tput setaf 1 >/dev/null 2>&1; then
  color_prompt=yes
fi
if [ "${color_prompt:-}" = yes ]; then
  PS1='\[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
else
  PS1='\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt
EOF
fi

# Auto-cd to /repo for normal SSH login shells only (safe for VS Code)
BASH_PROFILE="${HOME_DIR}/.bash_profile"
if [ ! -f "$BASH_PROFILE" ]; then
  touch "$BASH_PROFILE"
fi

if ! grep -q "dev-env: source bashrc" "$BASH_PROFILE" 2>/dev/null; then
  cat >> "$BASH_PROFILE" <<'EOF'

# --- dev-env: source bashrc ---
# SSH login shells read .bash_profile, not .bashrc, so source it explicitly.
if [ -f ~/.bashrc ]; then
  . ~/.bashrc
fi
EOF
fi

if ! grep -q "dev-env: clear screen" "$BASH_PROFILE" 2>/dev/null; then
  cat >> "$BASH_PROFILE" <<'EOF'

# --- dev-env: clear screen ---
# Keep SSH entry clean by clearing terminal before showing the prompt.
if [ -n "${SSH_TTY:-}" ] && [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
  clear 2>/dev/null || true
fi
EOF
fi

if ! grep -q "dev-env: auto-cd" "$BASH_PROFILE" 2>/dev/null; then
  cat >> "$BASH_PROFILE" <<'EOF'

# --- dev-env: auto-cd ---
# Only for interactive SSH login shells. Avoids breaking VS Code bootstrap.
if [ -n "${SSH_TTY:-}" ] && [ -t 1 ] && [ -d /repo ]; then
  cd /repo 2>/dev/null || true
fi
EOF
fi

# Seed Git identity from host values for brand-new environments.
# Do not overwrite user-set values already present in ~/.gitconfig.
if [ -n "$GIT_USER_NAME" ] || [ -n "$GIT_USER_EMAIL" ]; then
  GITCFG="${HOME_DIR}/.gitconfig"
  CUR_GIT_NAME="$(git config --file "$GITCFG" --get user.name 2>/dev/null || true)"
  CUR_GIT_EMAIL="$(git config --file "$GITCFG" --get user.email 2>/dev/null || true)"

  if [ -n "$GIT_USER_NAME" ] && [ -z "$CUR_GIT_NAME" ]; then
    git config --file "$GITCFG" user.name "$GIT_USER_NAME"
  fi
  if [ -n "$GIT_USER_EMAIL" ] && [ -z "$CUR_GIT_EMAIL" ]; then
    git config --file "$GITCFG" user.email "$GIT_USER_EMAIL"
  fi
fi

# fix perms for mounted home volume (includes .bashrc/.bash_profile)
chown -R "${DEV_USER}:${DEV_USER}" "$HOME_DIR"
chmod 755 "$HOME_DIR"

# ssh directory in home
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown -R "${DEV_USER}:${DEV_USER}" "$SSH_DIR"

# If Docker socket is mounted, grant DEV_USER access via matching group GID.
if [ -S /var/run/docker.sock ]; then
  SOCK_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || true)"
  if [ -n "$SOCK_GID" ]; then
    SOCK_GROUP="$(getent group "$SOCK_GID" | cut -d: -f1 || true)"
    if [ -z "$SOCK_GROUP" ]; then
      SOCK_GROUP="docker-host"
      groupadd -f -g "$SOCK_GID" "$SOCK_GROUP" >/dev/null 2>&1 || true
    fi
    usermod -aG "$SOCK_GROUP" "$DEV_USER" >/dev/null 2>&1 || true
  fi
fi

# IMPORTANT: unlock account so SSH allows login
usermod -U "$DEV_USER" 2>/dev/null || true
passwd -u "$DEV_USER" 2>/dev/null || true
passwd -d "$DEV_USER" 2>/dev/null || true

ssh-keygen -A >/dev/null 2>&1 || true

exec "$@"
