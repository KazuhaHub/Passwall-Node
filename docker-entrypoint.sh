#!/bin/sh
# Docker mounts secrets read-only and commonly exposes them as mode 0444. The
# daemon deliberately rejects that mode, so root copies the enrollment secret
# into a private tmpfs file before permanently dropping privileges.
set -eu

# The Agent's own lines read "YYYY/MM/DD HH:MM:SS.ffffff [Severity] ...". BusyBox
# date cannot produce sub-second precision, so these pre-exec failures keep the
# same shape at second resolution rather than reintroducing a second dialect for
# operators to parse.
log_error() {
    printf '%s [Error] passwall-node: %s\n' "$(date -u '+%Y/%m/%d %H:%M:%S')" "$1" >&2
}
fatal() {
    log_error "$1"
    exit 1
}

case "${1:-}" in
    --version|--upgrade-info)
        exec /usr/local/bin/passwall-node "$1"
        ;;
    --run-docker-upgrade-helper)
        [ "$(id -u)" = 0 ] || fatal "Docker upgrade helper must run as root"
        exec /usr/local/bin/passwall-node "$1"
        ;;
esac

[ -n "${PSP_NODE_ENDPOINT:-}" ] || fatal "PSP_NODE_ENDPOINT is required"
[ -n "${PSP_NODE_AGENT_ID:-}" ] || fatal "PSP_NODE_AGENT_ID is required"

PUID="${PUID:-10001}"
PGID="${PGID:-10001}"
DATA_DIR="${PSP_NODE_DATA_DIR:-/var/lib/passwall-node}"
SECRET_SOURCE="${PSP_NODE_CREDENTIAL_FILE:-/run/secrets/node_credential}"
XRAY_API_LISTEN="${PSP_NODE_XRAY_API_LISTEN:-127.0.0.1:10085}"
SING_BOX_API_LISTEN="${PSP_NODE_SING_BOX_API_LISTEN:-127.0.0.1:10086}"
CREDENTIAL_FILE="$SECRET_SOURCE"

case "$PUID" in ''|*[!0-9]*|0) fatal "PUID must be a non-zero numeric ID" ;; esac
case "$PGID" in ''|*[!0-9]*|0) fatal "PGID must be a non-zero numeric ID" ;; esac

case "${PSP_NODE_ALLOW_INSECURE_HTTP:-false}" in
    true|1|yes) INSECURE_FLAG="--allow-insecure-http" ;;
    false|0|no|'') INSECURE_FLAG="" ;;
    *) fatal "PSP_NODE_ALLOW_INSECURE_HTTP must be true or false" ;;
esac

if [ "$(id -u)" = "0" ]; then
    if [ ! -f "$SECRET_SOURCE" ]; then
        if [ -d "$SECRET_SOURCE" ]; then
            fatal "credential path is a directory, not a file: $SECRET_SOURCE; create the credential file before starting Docker and verify the mounted filename"
        fi
        fatal "credential secret is missing or is not a regular file: $SECRET_SOURCE"
    fi

    mkdir -p "$DATA_DIR" /run/passwall-node || fatal "cannot create the data or runtime directory"
    # THE RUNTIME DIRECTORY STAYS ROOT'S; ONLY THE CREDENTIAL IS HANDED OVER.
    #
    # This container drops ALL capabilities and adds back CHOWN, FOWNER, SETGID and
    # SETUID, so root here has no CAP_DAC_OVERRIDE — and a mode-0700 directory it has
    # chowned to PUID is one it can no longer stat or write into. Handing the directory
    # over and THEN copying into it, which is what this did, fails on EVERY start with
    #
    #     cp: can't stat '/run/passwall-node/credential': Permission denied
    #
    # and the container restarts forever. So root keeps the directory, at 0711: the
    # agent can traverse it and cannot list it, and nothing but root can write there.
    #
    # The stale credential is REMOVED rather than overwritten, for the same reason: a
    # PUID-owned 0600 file is one root cannot open for writing either. Removing needs
    # write permission on the directory, which root has.
    chmod 0711 /run/passwall-node || fatal "cannot protect the runtime directory"
    CREDENTIAL_FILE=/run/passwall-node/credential
    rm -f "$CREDENTIAL_FILE" || fatal "cannot clear the runtime credential"
    umask 077
    cp "$SECRET_SOURCE" "$CREDENTIAL_FILE" || fatal "cannot copy the credential into private runtime storage"
    chmod 0600 "$CREDENTIAL_FILE" || fatal "cannot protect the runtime credential"
    chown "$PUID:$PGID" "$CREDENTIAL_FILE" || fatal "cannot set runtime credential ownership"
    # Alpine ships BusyBox find, which does not implement GNU find's -uid or
    # -gid predicates. Keep the startup ownership repair portable: DATA_DIR is
    # the dedicated persistent state directory, so recursively assigning it to
    # the configured runtime identity is both bounded and intentional.
    if ! chown -R "$PUID:$PGID" "$DATA_DIR"; then
        fatal "cannot make $DATA_DIR owned by PUID=$PUID PGID=$PGID; allow ownership changes or set PUID/PGID to the bind-directory owner"
    fi
    if ! su-exec "$PUID:$PGID" test -w "$DATA_DIR"; then
        fatal "$DATA_DIR is not writable by PUID=$PUID PGID=$PGID; fix the bind-directory ownership or set matching PUID/PGID"
    fi

    # The optional updater sidecar creates a root-owned control marker. Give it
    # a short bounded startup window, but never make proxy startup depend on a
    # privileged helper: an unavailable helper simply disables remote upgrade.
    if [ "${PSP_NODE_DOCKER_REMOTE_UPGRADE:-false}" = "true" ]; then
        wait_count=0
        while [ "$wait_count" -lt 15 ] && [ ! -r /run/passwall-node-upgrades/enabled ]; do
            wait_count=$((wait_count + 1))
            sleep 1
        done
    fi

    if [ -n "$INSECURE_FLAG" ]; then
        exec su-exec "$PUID:$PGID" /usr/local/bin/passwall-node \
            --endpoint "$PSP_NODE_ENDPOINT" \
            --agent-id "$PSP_NODE_AGENT_ID" \
            --credential-file "$CREDENTIAL_FILE" \
            --data-dir "$DATA_DIR" \
            --xray-api-listen "$XRAY_API_LISTEN" \
            --sing-box-api-listen "$SING_BOX_API_LISTEN" \
            "$INSECURE_FLAG" "$@"
    fi
    exec su-exec "$PUID:$PGID" /usr/local/bin/passwall-node \
        --endpoint "$PSP_NODE_ENDPOINT" \
        --agent-id "$PSP_NODE_AGENT_ID" \
        --credential-file "$CREDENTIAL_FILE" \
        --data-dir "$DATA_DIR" \
        --xray-api-listen "$XRAY_API_LISTEN" \
        --sing-box-api-listen "$SING_BOX_API_LISTEN" \
        "$@"
fi

if [ -n "$INSECURE_FLAG" ]; then
    exec /usr/local/bin/passwall-node \
        --endpoint "$PSP_NODE_ENDPOINT" \
        --agent-id "$PSP_NODE_AGENT_ID" \
        --credential-file "$CREDENTIAL_FILE" \
        --data-dir "$DATA_DIR" \
        --xray-api-listen "$XRAY_API_LISTEN" \
        --sing-box-api-listen "$SING_BOX_API_LISTEN" \
        "$INSECURE_FLAG" "$@"
fi
exec /usr/local/bin/passwall-node \
    --endpoint "$PSP_NODE_ENDPOINT" \
    --agent-id "$PSP_NODE_AGENT_ID" \
    --credential-file "$CREDENTIAL_FILE" \
    --data-dir "$DATA_DIR" \
    --xray-api-listen "$XRAY_API_LISTEN" \
    --sing-box-api-listen "$SING_BOX_API_LISTEN" \
    "$@"
