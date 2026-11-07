#!/usr/bin/env bash
# Starts disposable Debian, Arch and Ubuntu hosts for trying sensible against,
# and writes a matching config and environment to .work/. Source .work/env.sh
# afterwards to use them, e.g.:
#
#   ./up.sh && source .work/env.sh
#   go generate ../../... && go build -o .work/sensible ../../cmd/sensible
#   .work/sensible bootstrap deb1 --user root --host-key "$(fingerprint 2211)"
#   .work/sensible apply --yes
#
# The containers run systemd, so they need a Docker daemon that allows
# --privileged and doesn't set no-new-privileges. Remove them with
# `docker rm -f deb1 arch1 ubu24 ubu26`.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work="$here/.work"
rm -rf "$work/config"
mkdir -p "$work/config"

[[ -f "$work/rootkey" ]] || ssh-keygen -q -t ed25519 -N '' -C test-root -f "$work/rootkey"
cp "$work/rootkey.pub" "$here/rootkey.pub"
[[ -f "$work/age.key" ]] || (cd "$here/../.." && go run filippo.io/age/cmd/age-keygen -o "$work/age.key" 2>/dev/null)
recipient=$(grep 'public key' "$work/age.key" | awk '{print $NF}')

docker build -q -t sensible-test-debian -f "$here/Containerfile.debian" "$here" >/dev/null
docker build -q -t sensible-test-arch -f "$here/Containerfile.arch" "$here" >/dev/null
docker build -q -t sensible-test-ubuntu24 -f "$here/Containerfile.ubuntu" \
    --build-arg RELEASE=24.04 "$here" >/dev/null
docker build -q -t sensible-test-ubuntu26 -f "$here/Containerfile.ubuntu" \
    --build-arg RELEASE=26.04 --build-arg EXTRA=sudo-rs "$here" >/dev/null
rm -f "$here/rootkey.pub"

start() {
    docker rm -f "$1" >/dev/null 2>&1 || true
    docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        --name "$1" --hostname "$1" -p "127.0.0.1:$3:22" "$2" >/dev/null
}
start deb1 sensible-test-debian 2211
start arch1 sensible-test-arch 2212
start ubu24 sensible-test-ubuntu24 2213
start ubu26 sensible-test-ubuntu26 2214

cp -r "$here/config/." "$work/config/"
# Lets chris log in and sudo with the test key, through a forwarded agent.
mkdir -p "$work/config/roles/rssh"
cat > "$work/config/roles/rssh/role.yml" <<YAML
sshd:
  authorized_keys:
    chris:
      - $(cat "$work/rootkey.pub")

pam_rssh:
  keys:
    - $(cat "$work/rootkey.pub")
YAML
cat > "$work/config/sensible.yml" <<YAML
secrets:
  recipients:
    - $recipient
  identity_command:
    - cat
    - $work/age.key
YAML
mkdir -p "$work/config/hosts.d"
cat > "$work/config/hosts.d/deb1.yml" <<YAML
deb1:
  address: 127.0.0.1:2211
  roles:
    base:
    vim:
    sshd:
    rssh:
    zsh:
      prompt_colours:
        chris: yellow
YAML
cat > "$work/config/hosts.d/arch1.yml" <<YAML
arch1:
  address: 127.0.0.1:2212
  roles:
    base:
    vim:
    sshd:
    rssh:
    zsh:
YAML
cat > "$work/config/hosts.d/ubu24.yml" <<YAML
ubu24:
  address: 127.0.0.1:2213
  roles:
    base:
    vim:
    sshd:
    rssh:
    zsh:
YAML
cat > "$work/config/hosts.d/ubu26.yml" <<YAML
ubu26:
  address: 127.0.0.1:2214
  roles:
    base:
    vim:
    sshd:
    rssh:
    zsh:
YAML

cat > "$work/env.sh" <<ENV
export SENSIBLE_CONFIG="$work/config"
export SSH_AUTH_SOCK="\${XDG_RUNTIME_DIR:-/tmp}/sensible-test-agent.sock"
if ! ssh-add -l >/dev/null 2>&1; then
    rm -f "\$SSH_AUTH_SOCK"
    ssh-agent -a "\$SSH_AUTH_SOCK" >/dev/null
    ssh-add -q "$work/rootkey"
fi
# Prints a test host's ed25519 fingerprint, for bootstrap --host-key.
fingerprint() {
    ssh-keyscan -t ed25519 -p "\$1" 127.0.0.1 2>/dev/null | ssh-keygen -lf - | awk '{print \$2}'
}
ENV
