FROM ubuntu:24.04

ARG DOCKER_COMPOSE_VERSION=v2.27.1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sudo git curl ca-certificates bash vim cloc \
    docker.io \
    build-essential pkg-config python3 python3-pip \
    bubblewrap \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /var/run/sshd \
  && ssh-keygen -A

# Install Docker Compose v2 CLI plugin system-wide.
RUN mkdir -p /usr/local/lib/docker/cli-plugins \
 && arch="$(uname -m)" \
 && case "$arch" in \
      x86_64) compose_arch="x86_64" ;; \
      aarch64|arm64) compose_arch="aarch64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-compose \
    "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
 && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Enable colored prompt
RUN sed -i 's/^#force_color_prompt=yes/force_color_prompt=yes/' /etc/skel/.bashrc

# Disable Ubuntu login noise
RUN rm -f /etc/motd \
    && rm -f /etc/update-motd.d/* \
    && sed -i 's/^PrintLastLog.*/PrintLastLog no/' /etc/ssh/sshd_config \
    && sed -i 's/^#PrintLastLog.*/PrintLastLog no/' /etc/ssh/sshd_config \
    && sed -i 's/^UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# SSH hardening
RUN sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

RUN git config --system init.defaultBranch main

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd","-D","-e"]
