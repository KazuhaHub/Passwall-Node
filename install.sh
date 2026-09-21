#!/bin/sh
# Public credential-free bootstrap. By default it installs Passwall Node from a
# published GitHub release, then hands all secret input to the local pn connect
# workflow. A release archive can also install without network access.
set +x
set -eu
umask 077
unset ENV BASH_ENV CDPATH

source_mode=github
setup_mode=configure
channel_override=
usage() {
    cat <<'USAGE'
Usage: install.sh [--channel stable|beta] [--install-only] [--offline]

  (no arguments)   Install the newest stable release and open PSP setup.
  --channel VALUE  Select stable or beta without a channel prompt.
  --install-only   Install the service and pn command without configuring PSP.
  --offline        Install the binary beside this script; use from an extracted
                   official Linux release archive without contacting GitHub.

Examples:
  curl .../install.sh | sudo sh
  curl .../install.sh | sudo sh -s -- --channel beta
  curl .../install.sh | sudo sh -s -- --install-only
  sudo ./install.sh --offline
  sudo ./install.sh --offline --install-only
USAGE
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-only) setup_mode=install ;;
        --offline) source_mode=offline ;;
        --channel)
            shift
            [ "$#" -gt 0 ] || { printf '%s\n' 'Missing value for --channel' >&2; usage >&2; exit 2; }
            channel_override=$1
            ;;
        --channel=*) channel_override=${1#--channel=} ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
case "$channel_override" in ''|stable|beta) ;; *) printf 'Invalid channel: %s\n' "$channel_override" >&2; usage >&2; exit 2 ;; esac
if [ "$source_mode" = offline ] && [ -n "$channel_override" ]; then
    printf '%s\n' '--channel cannot be combined with --offline' >&2
    usage >&2
    exit 2
fi

phase_number=1
phase_name=preflight
failed=0
phase() {
    phase_number=$1
    phase_name=$2
    printf 'Passwall Node [%s/6] %s\n' "$phase_number" "$phase_name"
}
fail() {
    failed=1
    printf 'Passwall Node [%s/6] ERROR (%s): %s\n' "$phase_number" "$phase_name" "$1" >&2
    exit 1
}

phase 1 'Check platform and prerequisites'
[ "$(id -u)" = 0 ] || fail 'run this public installer as root'
[ "$(uname -s)" = Linux ] || fail 'only Linux is supported by this installer'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'only amd64 and arm64 are supported' ;;
esac
for tool in awk mktemp install getent useradd chown mv mkdir chmod rm rmdir systemctl timeout ln readlink cp dirname basename; do
    command -v "$tool" >/dev/null 2>&1 || fail "required installation command is unavailable: $tool"
done
if [ "$source_mode" = github ]; then
    for tool in curl sha256sum tar; do
        command -v "$tool" >/dev/null 2>&1 || fail "required download command is unavailable: $tool"
    done
fi
[ -d /run/systemd/system ] || fail 'a running systemd host is required'

root=/opt/passwall-node
unit=/etc/systemd/system/passwall-node.service
pn_link=/usr/local/bin/pn
lock=/opt/.passwall-node-install.lock
stage=
unit_tmp=
cleanup() {
    result=$?
    if [ "$result" -ne 0 ] && [ "$failed" = 0 ]; then
        printf 'Passwall Node [%s/6] ERROR (%s): installation stopped; inspect this phase before retrying\n' "$phase_number" "$phase_name" >&2
    fi
    [ -z "$stage" ] || rm -rf -- "$stage"
    [ -z "$unit_tmp" ] || rm -f -- "$unit_tmp"
    rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ ! -e "$root" ] && [ ! -L "$root" ] || fail 'Passwall Node is already installed; use pn to manage it'
[ ! -e "$unit" ] && [ ! -L "$unit" ] || fail 'an existing Passwall Node systemd unit requires manual inspection'
existing_pn=$(command -v pn 2>/dev/null || true)
[ -z "$existing_pn" ] || fail "the pn command already exists at $existing_pn and was not replaced"
if [ -e "$pn_link" ] || [ -L "$pn_link" ]; then
    fail 'the pn command path already exists and was not replaced'
fi
mkdir "$lock" 2>/dev/null || fail 'another installation is running; inspect the installation lock manually'
stage=$(mktemp -d /opt/.passwall-node-public.XXXXXX) || fail 'cannot create a private staging directory'

# --- Release identity, resolved from the release document ---------------------
#
# THE INSTALLER NO LONGER DERIVES THE VERSION FROM THE TAG, and it no longer
# builds the download address. It reads the release's asset URLs, requires every
# one of them to address a download in this repository, and takes the platform's
# archive from the URL it is about to fetch. The version is then read out of that
# asset's NAME, and it is a CANDIDATE rather than a fact: nothing that depends on
# it happens until the checksum and the archive members have verified, and the
# binary reports the same version back.
#
# ONE NAME CANNOT BOTH ADDRESS AND NAME THE FILE, which is what the old shape got
# wrong. It built `releases/download/<tag>/<asset>` from a single value taken out
# of `tag_name` and called the version, so for a product release — tag `v4.0.0`,
# version `4.0.0` — that value was wrong for one of the two jobs whichever it was.
# The four releases published before the address changed make the same point from
# the other side: their tag carries a slash, which is two path segments rather than
# an error anyone would see.

release_repository_prefix='https://github.com/KazuhaHub/Passwall-Node/releases/download/'

# one_line <failure> <values> — require exactly one non-empty line, then print it.
#
# Every selection rule below is "there is exactly one of these", because a rule
# that takes the first of several picks by an order nobody stated.
one_line() {
    if [ "$(printf '%s' "$2" | grep -c '^.' || true)" != 1 ]; then
        fail "$1"
    fi
    printf '%s\n' "$2"
}

# resolve_release <release-document> <arch>
#
# Sets: release_tag, version, release_archive_url, release_manifest_url
resolve_release() {
    document=$1
    want_arch=$2

    # THE NEWEST IS CHOSEN, NOT ASSUMED TO BE FIRST. `releases[0]` was taken for
    # the newest because the API is documented to answer in that order, and against
    # the live repository it is not: a release published two hours after another sat
    # at index one, and nothing in the response explains the ordering. The axis that
    # cannot be reinterpreted is the release's OWN publication time, which the API
    # states per release — an ISO-8601 UTC instant, so ordering the strings is
    # ordering the instants.
    #
    # NONE AND UNPAIRABLE ARE SEPARATE MESSAGES. `curl --fail` rejects an HTTP error
    # before this runs, but a proxy or a captive portal answers 200 with a body that
    # is not a release at all, and the operator needs to be sent to the channel
    # rather than to a second release that does not exist.
    tags=$(sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' "$document")
    published=$(sed -n 's/.*"published_at": "\([^"]*\)".*/\1/p' "$document")
    [ -n "$tags" ] || fail 'the release source named no release; check that the channel has a published release'
    # THE LISTS GO IN THROUGH THE ENVIRONMENT, NOT `-v`. `-v` processes escape
    # sequences in its value, so a multi-line list arrives broken and awk reports a
    # newline inside a string — a failure about the mechanism rather than about the
    # releases. ENVIRON is passed through verbatim.
    release_tag=$(RELEASE_TAGS="$tags" RELEASE_TIMES="$published" awk 'BEGIN {
        n = split(ENVIRON["RELEASE_TAGS"], T, "\n"); m = split(ENVIRON["RELEASE_TIMES"], P, "\n")
        # A RELEASE WITHOUT A TIME CANNOT BE ORDERED, and guessing which one is
        # newest is how an older build gets installed. The counts are compared
        # first because a response where they differ is not a page of releases.
        if (n != m || n == 0) exit 1
        best = 1
        for (i = 2; i <= n; i++) if (P[i] > P[best]) best = i
        print T[best]
    }') || fail 'the release source did not give a publication time for every release, so the newest cannot be chosen'
    [ -n "$release_tag" ] || fail 'the release source named no release; check that the channel has a published release' 

    # ORIGIN FIRST, THEN THE RELEASE'S OWN NAME. Every candidate has to address a
    # download in this repository before any name is read out of it, so a document
    # that points elsewhere yields nothing to select rather than something to
    # fetch. The test is a LITERAL prefix (`index(...) == 1`) rather than a regex:
    # the prefix contains dots that would match any character, and a lookalike host
    # must not satisfy a check whose whole job is to pin the origin.
    all_urls=$(sed -n 's/.*"browser_download_url": "\([^"]*\)".*/\1/p' "$document")
    [ -n "$all_urls" ] || fail 'the release source advertised no downloadable assets'
    mine=$(printf '%s\n' "$all_urls" | awk -v prefix="$release_repository_prefix" 'index($0, prefix) == 1')
    [ -n "$mine" ] || fail 'the release source advertised no download from this repository'

    # AND THEN TO THE CHOSEN RELEASE, BY ITS TAG. The page may describe several, and
    # every asset's own address carries the tag it belongs to — so the same string
    # that chose the release chooses its files, and one release's assets can no
    # longer be paired with another's tag. A page with assets but none under this
    # release is the tag and the addresses disagreeing about the identity, which
    # deserves its own message rather than "no downloadable assets".
    urls=$(printf '%s\n' "$mine" | awk -v prefix="$release_repository_prefix$release_tag/" 'index($0, prefix) == 1')
    [ -n "$urls" ] || fail "release ${release_tag} does not address the assets it advertises"

    # THE ARCHIVE IS THE ONE CANONICAL NAME FOR THIS PLATFORM, AND ONLY ONE.
    # Missing and duplicated are both refusals. The name carries the version, so
    # the shape test admits EITHER scheme — a legacy version keeps its `v` prefix
    # and a product version is three integers — and that is a shape test on a
    # published file name, not the tag-to-version rule its publisher owns.
    selected=$(printf '%s\n' "$urls" | awk -v arch="$want_arch" '
        {
            name = $0
            sub(/^.*\//, "", name)
            # EVERY INTERPOLATED PATTERN IS A STRING, NEVER A LITERAL, and that is
            # not style. In a regex LITERAL (`/x\\.y/`) the `\\.` is a backslash
            # followed by any character; in a STRING the same text reaches the
            # matcher as `\.`, a literal dot. Mixing the two forms — a literal
            # opened and then concatenated with `arch` — produced a pattern that
            # silently never matched, so the version came out with the file suffix
            # still attached and the installer refused a release that was fine.
            legacy  = "^passwall-node_v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?_linux_" arch "\\.tar\\.gz$"
            product = "^passwall-node_(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*))?_linux_" arch "\\.tar\\.gz$"
            if (name ~ legacy || name ~ product) {
                version = name
                sub(/^passwall-node_/, "", version)
                sub("_linux_" arch "\\.tar\\.gz$", "", version)
                print version " " $0
            }
        }')
    if [ "$(printf '%s' "$selected" | grep -c '^.' || true)" != 1 ]; then
        fail "the release must offer exactly one linux/${want_arch} archive with a canonical name"
    fi
    version=${selected%% *}
    release_archive_url=${selected#* }

    # THE NAME THAT GETS VERIFIED IS THE NAME THAT WAS FOUND, and this is where
    # the two are made to be one string rather than assumed to be.
    case "$release_archive_url" in
        */"passwall-node_${version}_linux_${want_arch}.tar.gz") ;;
        *) fail 'the selected asset name does not match the platform it was selected for' ;;
    esac

    release_manifest_url=$(one_line 'the release must offer exactly one SHA256SUMS.txt' \
        "$(printf '%s\n' "$urls" | grep '/SHA256SUMS\.txt$' || true)")
}

if [ "$source_mode" = offline ]; then
    phase 2 'Inspect the extracted offline release package'
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || fail 'cannot resolve the offline package directory'
    for name in passwall-node LICENSE NOTICE; do
        [ -f "$script_dir/$name" ] && [ ! -L "$script_dir/$name" ] || fail "offline package member is missing or unsafe: $name"
    done
    [ -x "$script_dir/passwall-node" ] || fail 'offline package binary is not executable'
    "$script_dir/passwall-node" --version > "$stage/source-version" || fail 'offline package binary cannot execute'
    IFS=' ' read -r version ignored < "$stage/source-version"
    package="passwall-node_${version}_linux_${arch}"
    [ "$(basename -- "$script_dir")" = "$package" ] || fail 'offline package directory does not match its binary version and platform'
    channel=offline
else
    phase 2 'Resolve a published release'
    channel=${channel_override:-${PN_CHANNEL:-stable}}
    # ONE RELEASE PER PAGE. The beta channel wants the newest release including
    # pre-releases, which `releases/latest` will not answer, so it asks the list
    # endpoint for a single element instead of paging twenty and taking the first
    # — that is the same release (the API answers newest-first either way) with no
    # other release's assets in the document to be mixed up with it.
    case "$channel" in
        stable) releases_url=https://api.github.com/repos/KazuhaHub/Passwall-Node/releases/latest ;;
        beta) releases_url='https://api.github.com/repos/KazuhaHub/Passwall-Node/releases?per_page=20' ;;
        *) fail 'PN_CHANNEL must be stable or beta' ;;
    esac
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 60 --max-filesize 1048576 --output "$stage/releases.json" "$releases_url" || \
        fail "cannot resolve the latest $channel release"
    resolve_release "$stage/releases.json" "$arch"
fi
# THE VERSION IS EITHER SCHEME, and this check sits here because BOTH sources
# reach it: the offline path reads it from the binary beside the script, the
# network path reads it out of the asset name. A legacy version carries its `v`
# prefix; a product version is three integers with no prefix.
case "$version" in *[!0-9A-Za-z._-]*) fail "the selected release source returned an unsafe version: $version" ;; esac
printf '%s\n' "$version" | awk '
    /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/ { ok = 1 }
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/ { ok = 1 }
    END { exit !ok }' || \
    fail "the selected release source returned a non-canonical version: $version"

package="passwall-node_${version}_linux_${arch}"
asset="${package}.tar.gz"
# THE ADDRESSES COME FROM THE RELEASE DOCUMENT, not from a template. They were
# checked to address this repository, to carry the release's own tag and to end in
# the canonical name the version was read from, so nothing here has to reconstruct
# a URL — and nothing here can get the reconstruction wrong.
if [ "$source_mode" = github ]; then
    phase 3 "Download $version ($channel, linux/$arch)"
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --max-filesize 1048576 --output "$stage/SHA256SUMS.txt" "$release_manifest_url" || \
        fail 'checksum manifest download failed'
    if [ -t 2 ]; then
        curl --disable --fail --progress-bar --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 15 --max-time 300 --output "$stage/$asset" "$release_archive_url" || fail 'release archive download failed'
    else
        curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 15 --max-time 300 --output "$stage/$asset" "$release_archive_url" || fail 'release archive download failed'
    fi
else
    phase 3 "Stage $version from the offline package (linux/$arch)"
fi

phase 4 'Verify checksum, archive members and executable version'
mkdir "$stage/bundle" "$stage/bundle/bin" "$stage/bundle/config" "$stage/bundle/data" "$stage/bundle/licenses"
if [ "$source_mode" = github ]; then
    awk -v name="$asset" '$2 == name || $2 == "*" name { count++; sum=$1 } END { if (count != 1 || length(sum) != 64 || sum ~ /[^0-9a-fA-F]/) exit 1; print sum "  " name }' \
        "$stage/SHA256SUMS.txt" > "$stage/selected.sha256" || fail 'release checksum entry is missing, duplicated or invalid'
    (cd "$stage" && sha256sum --check --status selected.sha256) || fail 'release checksum verification failed'
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
else
    cp -- "$script_dir/passwall-node" "$stage/bundle/bin/passwall-node" || fail 'cannot stage the offline binary'
    cp -- "$script_dir/LICENSE" "$stage/bundle/licenses/LICENSE" || fail 'cannot stage the offline license'
    cp -- "$script_dir/NOTICE" "$stage/bundle/licenses/NOTICE" || fail 'cannot stage the offline notice'
fi
chmod 0755 "$stage/bundle/bin/passwall-node"
"$stage/bundle/bin/passwall-node" --version > "$stage/binary-version" || fail 'release binary cannot execute'
IFS=' ' read -r binary_version ignored < "$stage/binary-version"
[ "$binary_version" = "$version" ] || fail 'release binary version does not match the selected release'

phase 5 'Install program, service definition and pn command'
if ! getent passwd passwall-node > "$stage/account"; then
    useradd --system --user-group --home-dir "$root" --no-create-home --shell /usr/sbin/nologin passwall-node || \
        fail 'cannot create the dedicated service account'
    getent passwd passwall-node > "$stage/account" || fail 'cannot inspect the service account'
fi
IFS=: read -r account password uid gid gecos home shell < "$stage/account"
[ "$account" = passwall-node ] && [ "$home" = "$root" ] || fail 'existing service account is not dedicated to this installation'
case "$uid" in ''|0|*[!0-9]*) fail 'service account must have a non-root numeric UID' ;; esac
case "$shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;; *) fail 'service account must not have an interactive shell' ;; esac
printf '%s\n' "$version" > "$stage/bundle/config/version"
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
chmod 0700 "$stage/bundle/config" "$stage/bundle/data"
chmod 0755 "$stage/bundle" "$stage/bundle/bin" "$stage/bundle/licenses"
chmod 0644 "$stage/bundle/licenses/LICENSE" "$stage/bundle/licenses/NOTICE" "$stage/bundle/passwall-node.service"
chmod 0600 "$stage/bundle/config/version"
chown -R passwall-node:passwall-node "$stage/bundle/config" "$stage/bundle/data"
mv "$stage/bundle" "$root"
unit_tmp=$(mktemp /etc/systemd/system/.passwall-node.service.XXXXXX)
install -m 0644 "$root/passwall-node.service" "$unit_tmp"
mv -f "$unit_tmp" "$unit"
unit_tmp=
ln -s "$root/bin/passwall-node" "$pn_link" || fail 'cannot create the pn command link'
"$root/bin/passwall-node" --enable-remote-upgrade > "$stage/helper-setup" 2>&1 || \
    fail 'remote upgrade helper setup failed; installed files were retained'
timeout --kill-after=5s 30s systemctl daemon-reload > "$stage/systemd-reload" 2>&1 || \
    fail 'systemd reload failed; installed files were retained'

if [ "$setup_mode" = install ]; then
    phase 6 'Finish installation without configuring PSP'
    printf '%s\n' 'Passwall Node is installed but not configured or started.'
    printf '%s\n' 'Run sudo pn connect when the PSP endpoint, Agent ID and credential are available.'
    exit 0
fi

phase 6 'Configure the PSP connection'
printf '%s\n' ' Passwall Node is installed but will not start until its PSP identity is configured.'
if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    if "$pn_link" connect </dev/tty >/dev/tty 2>&1; then
        printf '%s\n' 'Passwall Node installation and interactive configuration completed.'
    else
        fail 'interactive configuration did not complete; the installation was retained, so run sudo pn connect to retry'
    fi
else
    printf '%s\n' 'No interactive terminal is available. Run sudo pn connect to enter the values shown by PSP.'
fi
