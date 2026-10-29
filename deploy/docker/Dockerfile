# syntax=docker/dockerfile:1
# Baut beide Images direkt aus dem Quellcode (ohne GitHub-Release).
#
#   docker build -f deploy/docker/Dockerfile --target caddy -t caddy-sentinel .
#   docker build -f deploy/docker/Dockerfile --target panel -t caddy-sentinel-panel .
#
# Build-Argumente: VERSION, CADDY_VERSION (leer = go.mod, "latest"), UPGRADE_WAF=1

ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-alpine AS build
RUN apk add --no-cache build-base git
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG CADDY_VERSION=
ARG UPGRADE_WAF=0
ENV GOTOOLCHAIN=auto
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    case "$(go env GOARCH)" in arm) ARCH=armv7 ;; *) ARCH=$(go env GOARCH) ;; esac \
 && apk add --no-cache bash \
 && VERSION="$VERSION" ARCH="$ARCH" CADDY_VERSION="$CADDY_VERSION" UPGRADE_WAF="$UPGRADE_WAF" SKIP_TESTS=1 OUT=/out \
    bash scripts/build-release.sh \
 && mkdir -p /out/bin && cp /out/linux_*/caddy /out/linux_*/caddy-sentinel /out/bin/

FROM alpine:3.24 AS base
RUN apk add --no-cache ca-certificates tzdata libcap-utils mailcap \
 && addgroup -S -g 1000 caddy \
 && adduser -S -D -H -u 1000 -G caddy -h /data -s /sbin/nologin caddy
COPY deploy/docker/Caddyfile /usr/share/caddy-sentinel/Caddyfile.default
COPY deploy/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

FROM base AS caddy
COPY --from=build /out/bin/caddy /usr/bin/caddy
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy \
 && mkdir -p /data /config /run/caddy /var/lib/caddy-sentinel /srv /etc/caddy/sites \
 && chown -R caddy:caddy /data /config /run/caddy /etc/caddy /srv
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config \
    SENTINEL_PANEL=http://panel:7600 SENTINEL_TOKEN_FILE=/var/lib/caddy-sentinel/agent.token
USER caddy
EXPOSE 80 443 443/udp
VOLUME ["/data", "/config"]
WORKDIR /srv
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD test -S /run/caddy/admin.sock || wget -q -O /dev/null http://127.0.0.1:2019/config/
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

FROM base AS panel
COPY --from=build /out/bin/caddy-sentinel /usr/bin/caddy-sentinel
COPY --from=build /out/bin/caddy /usr/bin/caddy
RUN mkdir -p /var/lib/caddy-sentinel /etc/caddy/sites /caddy-data /data /run/caddy \
 && chown -R caddy:caddy /var/lib/caddy-sentinel /etc/caddy /data /run/caddy /caddy-data
ENV SENTINEL_LISTEN=0.0.0.0:7600 SENTINEL_DATA=/var/lib/caddy-sentinel \
    SENTINEL_CADDY_ADMIN=unix//run/caddy/admin.sock SENTINEL_CADDYFILE=/etc/caddy/Caddyfile \
    SENTINEL_CADDY_BIN=/usr/bin/caddy SENTINEL_CADDY_DATA=/caddy-data/caddy XDG_DATA_HOME=/data
USER caddy
EXPOSE 7600
VOLUME ["/var/lib/caddy-sentinel"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -q -O /dev/null http://127.0.0.1:7600/api/auth/state || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "/usr/bin/caddy-sentinel"]
