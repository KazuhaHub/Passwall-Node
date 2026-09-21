#!/bin/sh
# This is a template, not a public credential-free bootstrap script. Render it
# with deployment.RenderLinux and keep the resulting file private (0600).
set +x
set -eu
umask 077
unset ENV BASH_ENV CDPATH credential

phase_number=1
phase_name=preflight
failure_reported=0
phase() {
    phase_number=$1
    phase_name=$2
    printf 'Passwall Node [%s/6] %s\n' "$phase_number" "$phase_name"
}
fail() {
    failure_reported=1
    printf 'Passwall Node [%s/6] ERROR (%s): %s\n' "$phase_number" "$phase_name" "$1" >&2
    exit 1
}
phase 1 'Check platform and prerequisites'
[ "$(id -u)" = 0 ] || fail 'run this private script as root'
[ "$(uname -s)" = Linux ] || fail 'only Linux is supported by this installer'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'only amd64 and arm64 are supported' ;;
esac
for tool in curl sha256sum tar awk date mktemp install getent useradd chown cmp mv mkdir chmod rm rmdir systemctl timeout sleep ln readlink; do
    command -v "$tool" >/dev/null 2>&1 || fail "required installation command is unavailable: $tool"
done
[ -d /run/systemd/system ] || fail 'a running systemd host is required'

version=@@VERSION@@
tag=@@TAG@@
# mode is what the control plane asked for: install a fresh node, upgrade the
# release of the one that is here, or replace it. It is a closed set and it is
# rendered, not derived: the script cannot tell an operator's intent from the
# filesystem.
mode=@@MODE@@
agent_id=@@AGENT_ID@@
endpoint=@@ENDPOINT@@
credential=@@CREDENTIAL@@
environment=@@ENVIRONMENT@@
case "$version$tag$mode" in *@@*) fail 'render this template with the control plane before installation' ;; esac
case "$mode" in
    install|upgrade|replace) ;;
    *) fail 'unknown installation mode' ;;
esac
root=/opt/passwall-node
unit=/etc/systemd/system/passwall-node.service
pn_link=/usr/local/bin/pn
lock=/opt/.passwall-node-install.lock
stage=
unit_tmp=
upgrade_backup=
retained=0
upgrading=0
replacing=0
# displaced is where the installation that `mode=replace` moves aside ends up. It is
# set only once that move has happened, which is what the cleanup trap keys on.
displaced=

# upgrade_info_field reads one numeric field of `--upgrade-info`, which is a single
# line of JSON with a fixed shape. It is pure shell on purpose: this installer's
# tool set is fixed (see phase 1), jq is not in it, and this is the only JSON the
# script reads. Anything absent or non-numeric yields nothing, which every caller
# treats as "cannot be established" and refuses on.
upgrade_info_field() {
    info=$("$1" --upgrade-info 2>/dev/null) || return 0
    marker="\"$2\":"
    case "$info" in
        *"$marker"*) ;;
        *) return 0 ;;
    esac
    rest=${info#*"$marker"}
    value=${rest%%,*}
    value=${value%%\}*}
    case "$value" in
        ''|*[!0-9]*) return 0 ;;
    esac
    printf '%s\n' "$value"
}

# replace_release_in_place swaps the release of an installation that is already here
# and keeps its identity: the binary, the version stamp and the licenses are
# replaced; data/, config/credential, config/environment, the service definition and
# the systemd unit are not. It is the same file set the remote upgrade helper
# manages (internal/upgrade/helper_linux.go) and the same order — gate, back up,
# stop, swap — with phase 6 starting the service again.
replace_release_in_place() {
    # THE STATE FORMAT IS THE ONE THING AN IN-PLACE SWAP CANNOT ROLL BACK BY KEEPING
    # A FILE. The daemon reads its data directory with the schema it was built
    # against, so the release being replaced and the release replacing it have to
    # agree on it. The remote upgrade helper refuses on the same comparison
    # (internal/upgrade/helper_linux.go); this is the same gate, run by the one piece
    # of new code that can reach a node too old for that helper.
    installed_schema=$(upgrade_info_field "$root/bin/passwall-node" state_schema)
    candidate_schema=$(upgrade_info_field "$stage/bundle/bin/passwall-node" state_schema)
    [ -n "$installed_schema" ] || fail 'the installed binary cannot report its state format; manual upgrade is required'
    [ -n "$candidate_schema" ] || fail 'the target release cannot report its state format; manual upgrade is required'
    [ "$installed_schema" = "$candidate_schema" ] || fail "the target release changes the state format ($installed_schema to $candidate_schema); manual upgrade is required"
    [ "$(upgrade_info_field "$root/bin/passwall-node" upgrade_contract)" = 1 ] || fail 'the installed binary does not support the upgrade contract; manual upgrade is required'
    [ "$(upgrade_info_field "$stage/bundle/bin/passwall-node" upgrade_contract)" = 1 ] || fail 'the target release does not support the upgrade contract; manual upgrade is required'

    phase 5 "Replace release $installed_version with $version; identity and state retained"
    backup="$root/backups/upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$root/backups" || fail 'cannot create the backup directory'
    chmod 0700 "$root/backups"
    mkdir "$backup" || fail 'cannot create the upgrade backup'
    install -m 0755 "$root/bin/passwall-node" "$backup/passwall-node" || fail 'cannot back up the installed binary'
    install -m 0600 "$root/config/version" "$backup/version" || fail 'cannot back up the installed version'
    install -m 0644 "$root/licenses/LICENSE" "$backup/LICENSE" || fail 'cannot back up the installed license'
    install -m 0644 "$root/licenses/NOTICE" "$backup/NOTICE" || fail 'cannot back up the installed notice'
    # FROM HERE THE INSTALLATION HAS CHANGED, so the EXIT trap owes it a rollback.
    upgrade_backup="$backup"
    # STOP FIRST: the running process holds the old binary's code, and swapping
    # the file under it would leave the two disagreeing about the state on disk.
    # Phase 6 starts it again — `enable --now` starts a unit that is not running.
    timeout --kill-after=5s 30s systemctl stop passwall-node.service || fail 'service stop failed or timed out; the installation was not changed'
    install -m 0755 "$stage/bundle/bin/passwall-node" "$root/bin/.passwall-node.new" || fail 'cannot stage the new binary'
    mv -f "$root/bin/.passwall-node.new" "$root/bin/passwall-node" || fail 'cannot publish the new binary'
    install -m 0600 "$stage/version" "$root/config/version" || fail 'cannot publish the new version'
    chown passwall-node:passwall-node "$root/config/version" || fail 'cannot hand the new version stamp to the service account'
    install -m 0644 "$stage/bundle/licenses/LICENSE" "$root/licenses/LICENSE" || fail 'cannot publish the license'
    install -m 0644 "$stage/bundle/licenses/NOTICE" "$root/licenses/NOTICE" || fail 'cannot publish the notice'
    # data/, config/credential, config/environment, the service definition and
    # the systemd unit are NOT touched: this replaces a release, not a node.
}

# move_installation_aside stops the service and moves the installation that is here
# to a path beside the root, so that a DIFFERENT identity can take the root over with
# nothing of the old one left in it. It is what `mode=replace` does that no other
# mode may: the fresh branch below requires the root to be free, and a replacement
# has to make it free.
#
# IT MOVES RATHER THAN COPIES. A copy would leave the credential, the release and the
# state directory exactly where the new identity is about to be installed — the new
# node would start against the old node's state, which is the one thing a new
# identity must not do. Preserving the old installation and emptying the path are
# therefore ONE operation, and a rename is the atomic way to do both. Nothing is
# discarded: the whole directory goes to a named path, and the caller moves it under
# the new installation's backups/ once the new installation is published.
#
# THE SERVICE IS STOPPED FIRST, AND PROVEN STOPPED. Starting a unit that is already
# active is a no-op, so an agent left running from the old root would keep running
# against the new identity's data directory — the old node's state written into a
# directory the panel no longer connects to it. The state is read back rather than
# trusted to the stop command: an installation that is still running is left exactly
# as it is, with nothing changed, and the operator is told which state it is in.
move_installation_aside() {
    if [ -e "$unit" ] || [ -L "$unit" ]; then
        timeout --kill-after=5s 30s systemctl stop passwall-node.service >/dev/null 2>&1 || true
        state=$(timeout --kill-after=1s 3s systemctl show passwall-node.service --property=ActiveState --value 2>/dev/null) || state=unknown
        case "$state" in
            inactive|failed) ;;
            *) fail "the service is $state and could not be stopped; nothing was changed" ;;
        esac
    fi
    displaced="$root.replaced-$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$root" "$displaced" || fail 'cannot move the installation that is here into the backup area; nothing was changed'
}

# restore_upgrade puts the previous release back after a failed in-place upgrade.
# It runs from the EXIT trap, so it must never fail the script it is already
# unwinding, and it reports what it could not do rather than hiding it.
restore_upgrade() {
    printf 'Passwall Node: restoring the previous release from %s\n' "$upgrade_backup" >&2
    # THE VERSION STAMP GOES BACK FIRST, and the order is the point: `config/version`
    # is what the NEXT run compares against. If the stamp comes back and the binary
    # does not, the node reports the old version while running the new one — the next
    # attempt sees a release that differs and swaps again, which is the self-healing
    # half of the two. The other order leaves a node that claims to be on a release
    # it is not, and no later run would notice.
    { install -m 0600 "$upgrade_backup/version" "$root/config/version" 2>/dev/null &&
        chown passwall-node:passwall-node "$root/config/version" 2>/dev/null; } ||
        printf 'Passwall Node: ERROR the previous version stamp could not be restored\n' >&2
    if ! install -m 0755 "$upgrade_backup/passwall-node" "$root/bin/.passwall-node.restore" 2>/dev/null ||
        ! mv -f "$root/bin/.passwall-node.restore" "$root/bin/passwall-node" 2>/dev/null; then
        printf 'Passwall Node: ERROR the previous binary could not be restored; repair this installation by hand\n' >&2
        return 0
    fi
    install -m 0644 "$upgrade_backup/LICENSE" "$root/licenses/LICENSE" 2>/dev/null ||
        printf 'Passwall Node: ERROR the previous license could not be restored\n' >&2
    install -m 0644 "$upgrade_backup/NOTICE" "$root/licenses/NOTICE" 2>/dev/null ||
        printf 'Passwall Node: ERROR the previous notice could not be restored\n' >&2
    timeout --kill-after=5s 30s systemctl start passwall-node.service 2>/dev/null ||
        printf 'Passwall Node: ERROR the previous release was restored but the service did not start; start it by hand\n' >&2
}

cleanup() {
    result=$?
    if [ "$result" -ne 0 ] && [ "$failure_reported" = 0 ]; then
        printf 'Passwall Node [%s/6] ERROR (%s): installation stopped; inspect this phase before retrying\n' "$phase_number" "$phase_name" >&2
    fi
    # A failed upgrade is the one failure that left the installation changed, so it
    # is the one that has to put it back.
    if [ "$result" -ne 0 ] && [ -n "$upgrade_backup" ]; then
        restore_upgrade
    fi
    # A REPLACEMENT THAT FAILED BEFORE IT PUBLISHED LEFT NO INSTALLATION AT ALL: the
    # old one was moved aside and the new one never arrived. Put the old one back —
    # the failure had nothing to do with it — and say so, because the alternative is
    # a host whose node is missing with its replacement in a backup path.
    #
    # ONCE THE NEW INSTALLATION IS PUBLISHED THE ROOT IS NOT FREE, and this does
    # nothing: the new identity is what the operator asked for, and the displaced
    # installation stays where it is for them to inspect.
    if [ "$result" -ne 0 ] && [ -n "$displaced" ] && [ ! -e "$root" ] && [ ! -L "$root" ]; then
        if mv "$displaced" "$root" 2>/dev/null; then
            printf 'Passwall Node: the installation that was here has been put back at %s\n' "$root" >&2
        else
            printf 'Passwall Node: ERROR the installation that was here is at %s and could not be put back; move it by hand\n' "$displaced" >&2
        fi
    fi
    [ -z "$stage" ] || rm -rf -- "$stage"
    [ -z "$unit_tmp" ] || rm -f -- "$unit_tmp"
    rmdir "$lock" 2>/dev/null || true
}
phase 2 'Check installation identity and exact version'
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
existing_pn=$(command -v pn 2>/dev/null || true)
if [ -n "$existing_pn" ]; then
    [ "$existing_pn" = "$pn_link" ] && [ -L "$pn_link" ] && [ "$(readlink "$pn_link")" = "$root/bin/passwall-node" ] || \
        fail "the pn command already exists at $existing_pn and is not managed by Passwall Node"
fi
if [ -e "$pn_link" ] || [ -L "$pn_link" ]; then
    [ -L "$pn_link" ] && [ "$(readlink "$pn_link")" = "$root/bin/passwall-node" ] || \
        fail 'the pn command path already exists and is not managed by Passwall Node'
fi

# NO REBIND, AND ONE NARROW EXCEPTION. An existing installation is never replaced
# by a different identity: the identity in this request must be the identity on
# disk, byte for byte, and an incomplete or foreign installation is preserved for
# operator inspection rather than overwritten.
#
# What the control plane may ask for instead is a different RELEASE for that SAME
# identity — an in-place upgrade — and only when it says so in `mode`. Without that
# word this behaves exactly as it always has: a release that differs is refused,
# because deciding to replace a running node's binary is not something a script
# should infer from a version string.
if [ -e "$root" ] || [ -L "$root" ]; then
    [ -d "$root" ] && [ ! -L "$root" ] || fail 'existing installation requires manual inspection'
    [ -d "$root/config" ] && [ ! -L "$root/config" ] && [ -d "$root/data" ] && [ ! -L "$root/data" ] || fail 'existing installation directories require manual inspection'
    if [ "$mode" = replace ]; then
        # A REPLACEMENT IS THE ONE THING THAT MAY DISAGREE WITH WHAT IS ON DISK, so
        # the byte comparisons below — which exist to prove the request describes the
        # installation that is already here — are exactly what it does not run. What
        # it needs instead is the version of the installation it will displace, for
        # the phase text and for the record the operator reads afterwards, and it
        # needs it read now: after phase 5 the file is gone.
        #
        # THE REST OF THIS PHASE IS SKIPPED FOR A REPLACEMENT, and that is a decision
        # rather than an omission: the checks below are repairs — a missing binary, a
        # missing unit — and a host whose node is in that state is one an operator
        # may well want to replace. What the replacement must be sure of is that the
        # directories are real, which is the line above, and that the service can be
        # stopped, which is move_installation_aside's job.
        read -r replaced_version < "$root/config/version" 2>/dev/null || replaced_version=''
        replacing=1
    else
    for file in credential environment; do
        [ -f "$root/config/$file" ] && [ ! -L "$root/config/$file" ] || fail 'existing installation is incomplete; inspect it manually'
        cmp -s "$stage/$file" "$root/config/$file" || fail 'existing identity, endpoint or credential differs; manual migration is required'
    done
    [ -f "$root/config/version" ] && [ ! -L "$root/config/version" ] || fail 'existing installation is incomplete; inspect it manually'
    [ -d "$root/bin" ] && [ ! -L "$root/bin" ] && [ -f "$root/bin/passwall-node" ] && [ ! -L "$root/bin/passwall-node" ] && [ -x "$root/bin/passwall-node" ] || fail 'existing binary requires manual repair'
    [ -f "$root/passwall-node.service" ] && [ ! -L "$root/passwall-node.service" ] || fail 'existing service definition requires manual repair'
    if cmp -s "$stage/version" "$root/config/version"; then
        retained=1
    else
        [ "$mode" = upgrade ] || fail 'existing identity, endpoint, credential or version differs; manual migration is required'
        read -r installed_version < "$root/config/version"
        upgrading=1
    fi
    fi
fi

if [ "$retained" = 1 ]; then
    phase 3 'Matching installation retained; download skipped (offline rerun)'
    phase 4 'Existing exact release retained; checksum download not repeated'
    phase 5 'Retain identity and state; configure service and optional upgrade helper'
else
    package="passwall-node_${version}_linux_${arch}"
    asset="${package}.tar.gz"
    # THE VERSION NAMES THE ASSET AND THE TAG IS WHERE THE RELEASE LIVES. They are
    # one string in the historical scheme and are never the same string now: a
    # product release is addressed as v4.0.0 and its archive is named
    # passwall-node_4.0.0_linux_amd64.tar.gz. Building the path from the version
    # asks for a release that does not exist under that name.
    #
    # AND THE TAG IS HANDED OVER RATHER THAN DERIVED, because a version no longer
    # determines one: the releases published before the address changed live at
    # release/4.0.1.2 and cannot move. Whoever rendered this script knew which
    # release was meant; this side does not have to guess.
    base="https://github.com/KazuhaHub/Passwall-Node/releases/download/${tag}"
    phase 3 "Download exact release $version (linux/$arch)"
    # Checksums detect corruption against the same trusted HTTPS release; they
    # are not a signature or protection against compromise of the publisher.
    # --disable must be first: local curl config must not override transport,
    # output or terminal-progress policy for this private installer.
    printf '%s\n' '  Downloading checksum manifest...'
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --output "$stage/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || fail 'checksum manifest download failed; no installation was published'
    printf '%s\n' '  Downloading release archive...'
    if [ -t 2 ]; then
        curl --disable --fail --progress-bar --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --output "$stage/$asset" "$base/$asset" || fail 'release archive download failed; no installation was published'
    else
        curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --output "$stage/$asset" "$base/$asset" || fail 'release archive download failed; no installation was published'
    fi
    phase 4 'Verify checksum, archive members and executable version'
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

    if [ "$upgrading" = 1 ]; then
        replace_release_in_place
    else
    if [ "$replacing" = 1 ]; then
        phase 5 "Replace the installation that is here; the displaced one is kept in the backup area"
    else
        phase 5 'Publish installation; configure service and optional upgrade helper'
    fi
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
    if [ "$replacing" = 1 ]; then
        move_installation_aside
    else
        [ ! -e "$root" ] && [ ! -L "$root" ] || fail 'installation appeared concurrently; inspect it manually'
    fi
    mv "$stage/bundle" "$root" || fail 'cannot publish the new installation'
    if [ -n "$displaced" ]; then
        # THE DISPLACED INSTALLATION MOVES UNDER THE NEW ONE, where an operator looks
        # for backups, and this is the FIRST step that may not abort the run: the new
        # node is published and the old one is safe at a path this prints, so failing
        # here would leave a host with no node over a directory move.
        if mkdir -p "$root/backups" && chmod 0700 "$root/backups" &&
            mv "$displaced" "$root/backups/replaced-$(date -u +%Y%m%dT%H%M%SZ)"; then
            printf '%s\n' '  The installation that was here is kept under backups/ on this host.'
        else
            printf 'Passwall Node: WARNING the installation that was here is still at %s; move it under %s/backups by hand\n' "$displaced" "$root" >&2
        fi
    fi
    fi
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
if [ ! -e "$pn_link" ] && [ ! -L "$pn_link" ]; then
    ln -s "$root/bin/passwall-node" "$pn_link" || fail 'cannot create the pn command link'
fi
# Older published binaries keep their original installation behavior. New
# binaries explicitly install the separate root helper, without changing the
# non-root agent unit or exposing an unauthenticated network upgrade endpoint.
if "$root/bin/passwall-node" --upgrade-info >/dev/null 2>&1; then
    printf '%s\n' '  Configuring supported remote-upgrade helper...'
    "$root/bin/passwall-node" --enable-remote-upgrade > "$stage/helper-setup" 2>&1 || fail 'remote upgrade setup failed; installed identity and data were retained'
else
    printf '%s\n' '  This release has no remote-upgrade helper; original behavior retained.'
fi
phase 6 'Start systemd service; agent process check has a 30s deadline'
printf '%s\n' '  Reloading systemd (30s deadline)...'
timeout --kill-after=5s 30s systemctl daemon-reload > "$stage/systemd-reload" 2>&1 || fail 'systemd reload failed or timed out; installed identity and data were retained'
printf '%s\n' '  Enabling and starting service (30s deadline)...'
timeout --kill-after=5s 30s systemctl enable --now passwall-node.service > "$stage/systemd-start" 2>&1 || fail 'service startup failed or timed out; installed identity and data were retained'
printf '%s\n' '  Waiting for active/running and a nonzero agent PID (30s total)...'
# The outer deadline bounds the entire polling loop; every individual D-Bus
# read also has a short bound. This proves only startup, not sync/proxy health.
timeout --kill-after=1s 30s sh -c '
    set -eu
    while :; do
        active=$(timeout --kill-after=1s 3s systemctl show passwall-node.service --property=ActiveState --value 2>/dev/null) || exit 1
        sub=$(timeout --kill-after=1s 3s systemctl show passwall-node.service --property=SubState --value 2>/dev/null) || exit 1
        pid=$(timeout --kill-after=1s 3s systemctl show passwall-node.service --property=MainPID --value 2>/dev/null) || exit 1
        case "$pid" in
            ""|*[!0-9]*) ;;
            *) if [ "$active" = active ] && [ "$sub" = running ] && [ "$pid" -gt 0 ]; then exit 0; fi ;;
        esac
        [ "$active" != failed ] || exit 1
        sleep 1
    done
' || fail 'agent did not reach active/running with a nonzero PID within 30s; installed identity and data were retained'
if [ "$replacing" = 1 ]; then
    printf '%s\n' 'Passwall Node installed; this host now reports a NEW identity and starts with empty state.'
fi
printf '%s\n' 'Passwall Node installed; identity and state retained under /opt/passwall-node.'
printf '%s\n' 'Local management is available through: pn'
printf '%s\n' 'Agent startup confirmed only. PSP sync, core and proxy readiness are not confirmed by this installer.'
printf '%s\n' 'Next: verify the server connection, core state and configured nodes in PSP, then test proxy traffic. Delete this private installation script securely.'
