#!/bin/sh
# This is a template, not a public credential-free bootstrap script. Render it
# with deployment.RenderLinux and keep the resulting file private (0600).
set +x
set -eu
umask 077
unset ENV BASH_ENV CDPATH credential

fail() { printf '%s\n' "passwall-node install: $1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'run this private script as root'
[ "$(uname -s)" = Linux ] || fail 'only Linux is supported by this installer'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'only amd64 and arm64 are supported' ;;
esac
for tool in curl sha256sum tar awk mktemp install getent useradd chown cmp mv mkdir chmod rm rmdir systemctl; do
    command -v "$tool" >/dev/null 2>&1 || fail 'a required installation command is unavailable'
done
[ -d /run/systemd/system ] || fail 'a running systemd host is required'

version=@@VERSION@@
agent_id=@@AGENT_ID@@
endpoint=@@ENDPOINT@@
credential=@@CREDENTIAL@@
environment=@@ENVIRONMENT@@
case "$version" in @@*) fail 'render this template with the control plane before installation' ;; esac
root=/opt/passwall-node
unit=/etc/systemd/system/passwall-node.service
lock=/opt/.passwall-node-install.lock
stage=
unit_tmp=
cleanup() {
    [ -z "$stage" ] || rm -rf -- "$stage"
    [ -z "$unit_tmp" ] || rm -f -- "$unit_tmp"
    rmdir "$lock" 2>/dev/null || true
}
mkdir "$lock" 2>/dev/null || fail 'another installation is running; inspect the installation lock manually'
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
stage=$(mktemp -d /opt/.passwall-node-stage.XXXXXX) || fail 'cannot create a private staging directory'
printf '%s\n' "$credential" > "$stage/credential"
printf '%s' "$environment" > "$stage/environment"
printf '%s\n' "$version" > "$stage/version"
unset credential

if { [ -e "$unit" ] || [ -L "$unit" ]; } && [ ! -e "$root" ] && [ ! -L "$root" ]; then
    fail 'existing systemd unit has no matching installation; manual migration is required'
fi

# No source/eval, no rebind or upgrade. Even an incomplete/foreign installation
# is preserved for operator inspection instead of replacing its data.
if [ -e "$root" ] || [ -L "$root" ]; then
    [ -d "$root" ] && [ ! -L "$root" ] || fail 'existing installation requires manual inspection'
    for file in credential environment version; do
        [ -f "$root/config/$file" ] && [ ! -L "$root/config/$file" ] || fail 'existing installation is incomplete; inspect it manually'
        cmp -s "$stage/$file" "$root/config/$file" || fail 'existing identity, endpoint, credential or version differs; manual migration is required'
    done
    [ -d "$root/config" ] && [ ! -L "$root/config" ] && [ -d "$root/data" ] && [ ! -L "$root/data" ] || fail 'existing installation directories require manual inspection'
    [ -d "$root/bin" ] && [ ! -L "$root/bin" ] && [ -f "$root/bin/passwall-node" ] && [ ! -L "$root/bin/passwall-node" ] && [ -x "$root/bin/passwall-node" ] || fail 'existing binary requires manual repair'
    [ -f "$root/passwall-node.service" ] && [ ! -L "$root/passwall-node.service" ] || fail 'existing service definition requires manual repair'
else
    package="passwall-node_${version}_linux_${arch}"
    asset="${package}.tar.gz"
    base="https://github.com/KazuhaHub/Passwall-Node/releases/download/${version}"
    # Checksums detect corruption against the same trusted HTTPS release; they
    # are not a signature or protection against compromise of the publisher.
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --output "$stage/SHA256SUMS.txt" "$base/SHA256SUMS.txt"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --output "$stage/$asset" "$base/$asset"
    awk -v name="$asset" '$2 == name || $2 == "*" name { count++; sum=$1 } END { if (count != 1 || length(sum) != 64 || sum ~ /[^0-9a-fA-F]/) exit 1; print sum "  " name }' "$stage/SHA256SUMS.txt" > "$stage/selected.sha256" || fail 'release checksum entry is missing, duplicated or invalid'
    (cd "$stage" && sha256sum --check --status selected.sha256) || fail 'release checksum verification failed'
    mkdir "$stage/bundle"
    mkdir "$stage/bundle/bin" "$stage/bundle/config" "$stage/bundle/data" "$stage/bundle/licenses"
    # Stream only three exact regular members to fresh private files. Never
    # extract archive paths, links, permissions or ownership into system paths.
    for name in passwall-node LICENSE NOTICE; do
        member="$package/$name"
        count=$(tar -tzf "$stage/$asset" | awk -v wanted="$member" '$0 == wanted { count++ } END { print count+0 }')
        [ "$count" = 1 ] || fail 'release archive has a missing or duplicate required member'
        kind=$(tar -tvzf "$stage/$asset" "$member")
        case "$kind" in -*) ;; *) fail 'release archive required member is not a regular file' ;; esac
        case "$name" in passwall-node) target="$stage/bundle/bin/passwall-node" ;; *) target="$stage/bundle/licenses/$name" ;; esac
        tar -xOzf "$stage/$asset" "$member" > "$target" || fail 'cannot read a required release member'
        [ -s "$target" ] || fail 'release archive contains an empty required member'
    done
    chmod 0755 "$stage/bundle/bin/passwall-node"
    # Confirm the target runs on this architecture and is stamped with exactly
    # the requested version before publishing any identity or data directory.
    "$stage/bundle/bin/passwall-node" --version > "$stage/binary-version" || fail 'release binary cannot execute'
    IFS=' ' read -r binary_version ignored < "$stage/binary-version"
    [ "$binary_version" = "$version" ] || fail 'release binary version does not match the selected release'

    if ! getent passwd passwall-node > "$stage/account"; then
        useradd --system --user-group --home-dir "$root" --no-create-home --shell /usr/sbin/nologin passwall-node || fail 'cannot create the dedicated service account'
        getent passwd passwall-node > "$stage/account" || fail 'cannot inspect the service account'
    fi
    IFS=: read -r account password uid gid gecos home shell < "$stage/account"
    [ "$account" = passwall-node ] && [ "$home" = "$root" ] || fail 'existing service account is not dedicated to this installation'
    case "$uid" in ''|0|*[!0-9]*) fail 'service account must have a non-root numeric UID' ;; esac
    case "$shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;; *) fail 'service account must not have an interactive shell' ;; esac
    install -m 0600 "$stage/credential" "$stage/bundle/config/credential"
    install -m 0600 "$stage/environment" "$stage/bundle/config/environment"
    install -m 0600 "$stage/version" "$stage/bundle/config/version"
    chmod 0700 "$stage/bundle/config" "$stage/bundle/data"
    chmod 0755 "$stage/bundle" "$stage/bundle/bin" "$stage/bundle/licenses"
    chmod 0644 "$stage/bundle/licenses/LICENSE" "$stage/bundle/licenses/NOTICE"
    chown -R passwall-node:passwall-node "$stage/bundle/config" "$stage/bundle/data"
    cat > "$stage/bundle/passwall-node.service" <<'UNIT'
[Unit]
Description=Passwall-Node native agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=passwall-node
Group=passwall-node
EnvironmentFile=/opt/passwall-node/config/environment
ExecStart=/opt/passwall-node/bin/passwall-node --endpoint ${PSP_NODE_ENDPOINT} --agent-id ${PSP_NODE_AGENT_ID} --credential-file /opt/passwall-node/config/credential --data-dir /opt/passwall-node/data
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/passwall-node/data

[Install]
WantedBy=multi-user.target
UNIT
    chmod 0644 "$stage/bundle/passwall-node.service"
    # Complete identity+credential+binary become visible in one same-filesystem
    # rename. Failed downloads/verification never leave a half-written identity.
    [ ! -e "$root" ] && [ ! -L "$root" ] || fail 'installation appeared concurrently; inspect it manually'
    mv "$stage/bundle" "$root"
fi

# Do not replace an unrelated/manual unit, including a linked unit. A matching
# rerun may repair a missing unit after interruption, not migrate a different one.
if [ -e "$unit" ] || [ -L "$unit" ]; then
    [ -f "$unit" ] && [ ! -L "$unit" ] && cmp -s "$root/passwall-node.service" "$unit" || fail 'existing systemd unit differs; manual migration is required'
fi
unit_tmp=$(mktemp /etc/systemd/system/.passwall-node.service.XXXXXX)
install -m 0644 "$root/passwall-node.service" "$unit_tmp"
mv -f "$unit_tmp" "$unit"
unit_tmp=
systemctl daemon-reload || fail 'systemd reload failed; installed identity and data were retained'
systemctl enable --now passwall-node.service || fail 'service startup failed; installed identity and data were retained'
printf '%s\n' 'Passwall-Node installed; identity and state retained under /opt/passwall-node. Delete this private installation script securely.'
