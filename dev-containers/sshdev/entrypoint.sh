#!/usr/bin/env bash
set -euo pipefail

DEV_USER="${DEV_USER:-dev}"
HOME_DIR="/home/${DEV_USER}"

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

# Ensure colored prompt even if skel was minimal
if ! grep -q "force_color_prompt" "${HOME_DIR}/.bashrc" 2>/dev/null; then
  cat >> "${HOME_DIR}/.bashrc" <<'EOF'

# --- dev-env: ensure colored prompt ---
force_color_prompt=yes
if [ -n "$force_color_prompt" ] && [ -x /usr/bin/tput ] && tput setaf 1 >/dev/null 2>&1; then
  color_prompt=yes
fi
if [ "$color_prompt" = yes ]; then
  PS1='\[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
else
  PS1='\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt
EOF
fi

# fix perms for mounted home volume
chown -R "${DEV_USER}:${DEV_USER}" "$HOME_DIR"
chmod 755 "$HOME_DIR"

mkdir -p "${HOME_DIR}/.ssh"
chmod 700 "${HOME_DIR}/.ssh"
chown -R "${DEV_USER}:${DEV_USER}" "${HOME_DIR}/.ssh"

# IMPORTANT: unlock account so SSH allows login
usermod -U "$DEV_USER" 2>/dev/null || true
passwd -u "$DEV_USER" 2>/dev/null || true
passwd -d "$DEV_USER" 2>/dev/null || true

ssh-keygen -A >/dev/null 2>&1 || true

exec "$@"
