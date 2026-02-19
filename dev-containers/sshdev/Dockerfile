FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sudo git curl ca-certificates bash \
    build-essential pkg-config python3 python3-pip \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /var/run/sshd \
  && ssh-keygen -A

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

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd","-D","-e"]
