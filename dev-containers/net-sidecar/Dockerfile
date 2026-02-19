FROM alpine:3.21

ARG SING_BOX_VERSION=1.10.7

RUN apk add --no-cache \
    bash \
    ca-certificates \
    iptables \
    iproute2 \
    libc-utils \
    wget

RUN set -eux; \
    arch="$(apk --print-arch)"; \
    case "$arch" in \
      x86_64) sb_arch="amd64" ;; \
      aarch64) sb_arch="arm64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    wget -qO /tmp/sing-box.tgz "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}.tar.gz"; \
    tar -xzf /tmp/sing-box.tgz -C /tmp; \
    install -m 0755 "/tmp/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}/sing-box" /usr/local/bin/sing-box; \
    rm -rf /tmp/sing-box*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD ip link show tun0 >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
