# Build the production daemon as a static Linux binary. BuildKit supplies
# TARGETOS/TARGETARCH for ordinary and multi-platform builds.
FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_DATE=""
RUN target_arch="${TARGETARCH:-$(go env GOARCH)}" && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${target_arch}" \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/KazuhaHub/passwall-node/internal/version.Version=${VERSION} \
        -X github.com/KazuhaHub/passwall-node/internal/version.Commit=${COMMIT} \
        -X github.com/KazuhaHub/passwall-node/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/passwall-node ./cmd/node

# The entrypoint starts as root only to turn a read-only Docker secret into the
# daemon's required mode-0600 credential and to repair the state-volume owner.
# It then execs the daemon through su-exec as an unprivileged numeric UID/GID.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata su-exec \
 && addgroup -g 10001 passwall-node \
 && adduser -D -H -u 10001 -G passwall-node passwall-node

ENV TZ=UTC \
    PSP_NODE_DATA_DIR=/var/lib/passwall-node \
    PSP_NODE_CREDENTIAL_FILE=/run/secrets/node_credential \
    PSP_NODE_XRAY_API_LISTEN=127.0.0.1:10085 \
    PSP_NODE_SING_BOX_API_LISTEN=127.0.0.1:10086 \
    PUID=10001 \
    PGID=10001

WORKDIR /var/lib/passwall-node
COPY --from=builder /out/passwall-node /usr/local/bin/passwall-node
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/passwall-node /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /var/lib/passwall-node /run/passwall-node \
 && chown -R 10001:10001 /var/lib/passwall-node /run/passwall-node

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
