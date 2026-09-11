#!/bin/sh
# Docker mounts secrets read-only and commonly exposes them as mode 0444. The
# daemon deliberately rejects that mode, so root copies the enrollment secret
# into a private tmpfs file before permanently dropping privileges.
set -eu

if [ "${1:-}" = "--version" ]; then
    exec /usr/local/bin/passwall-node --version
fi

: "${PSP_NODE_ENDPOINT:?PSP_NODE_ENDPOINT is required}"
: "${PSP_NODE_AGENT_ID:?PSP_NODE_AGENT_ID is required}"

PUID="${PUID:-10001}"
PGID="${PGID:-10001}"
DATA_DIR="${PSP_NODE_DATA_DIR:-/var/lib/passwall-node}"
SECRET_SOURCE="${PSP_NODE_CREDENTIAL_FILE:-/run/secrets/node_credential}"
XRAY_API_LISTEN="${PSP_NODE_XRAY_API_LISTEN:-127.0.0.1:10085}"
CREDENTIAL_FILE="$SECRET_SOURCE"

case "$PUID" in ''|*[!0-9]*|0) echo "passwall-node: PUID must be a non-zero numeric ID" >&2; exit 1 ;; esac
case "$PGID" in ''|*[!0-9]*|0) echo "passwall-node: PGID must be a non-zero numeric ID" >&2; exit 1 ;; esac

case "${PSP_NODE_ALLOW_INSECURE_HTTP:-false}" in
    true|1|yes) INSECURE_FLAG="--allow-insecure-http" ;;
    false|0|no|'') INSECURE_FLAG="" ;;
    *) echo "passwall-node: PSP_NODE_ALLOW_INSECURE_HTTP must be true or false" >&2; exit 1 ;;
esac

if [ "$(id -u)" = "0" ]; then
    if [ ! -f "$SECRET_SOURCE" ]; then
        echo "passwall-node: credential secret is not a regular file: $SECRET_SOURCE" >&2
        exit 1
    fi

    mkdir -p "$DATA_DIR" /run/passwall-node
    chown "$PUID:$PGID" /run/passwall-node
    chmod 0700 /run/passwall-node
    CREDENTIAL_FILE=/run/passwall-node/credential
    umask 077
    cp "$SECRET_SOURCE" "$CREDENTIAL_FILE"
    chmod 0600 "$CREDENTIAL_FILE"
    chown "$PUID:$PGID" "$CREDENTIAL_FILE"
    find "$DATA_DIR" \! -uid "$PUID" -exec chown "$PUID:$PGID" {} + 2>/dev/null || true

    if [ -n "$INSECURE_FLAG" ]; then
        exec su-exec "$PUID:$PGID" /usr/local/bin/passwall-node \
            --endpoint "$PSP_NODE_ENDPOINT" \
            --agent-id "$PSP_NODE_AGENT_ID" \
            --credential-file "$CREDENTIAL_FILE" \
            --data-dir "$DATA_DIR" \
            --xray-api-listen "$XRAY_API_LISTEN" \
            "$INSECURE_FLAG" "$@"
    fi
    exec su-exec "$PUID:$PGID" /usr/local/bin/passwall-node \
        --endpoint "$PSP_NODE_ENDPOINT" \
        --agent-id "$PSP_NODE_AGENT_ID" \
        --credential-file "$CREDENTIAL_FILE" \
        --data-dir "$DATA_DIR" \
        --xray-api-listen "$XRAY_API_LISTEN" \
        "$@"
fi

if [ -n "$INSECURE_FLAG" ]; then
    exec /usr/local/bin/passwall-node \
        --endpoint "$PSP_NODE_ENDPOINT" \
        --agent-id "$PSP_NODE_AGENT_ID" \
        --credential-file "$CREDENTIAL_FILE" \
        --data-dir "$DATA_DIR" \
        --xray-api-listen "$XRAY_API_LISTEN" \
        "$INSECURE_FLAG" "$@"
fi
exec /usr/local/bin/passwall-node \
    --endpoint "$PSP_NODE_ENDPOINT" \
    --agent-id "$PSP_NODE_AGENT_ID" \
    --credential-file "$CREDENTIAL_FILE" \
    --data-dir "$DATA_DIR" \
    --xray-api-listen "$XRAY_API_LISTEN" \
    "$@"
