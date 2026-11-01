#!/usr/bin/env bash
# Starts disposable Debian and Arch hosts for trying sensible against, and
# writes a matching config and environment to .work/. Source .work/env.sh
# afterwards to use them, e.g.:
#
#   ./up.sh && source .work/env.sh
#   go generate ../../... && go build -o .work/sensible ../../cmd/sensible
#   .work/sensible bootstrap deb1 --user root --host-key "$(fingerprint 2211)"
#   .work/sensible apply --yes
#
# The containers run systemd, so they need a Docker daemon that allows
# --privileged and doesn't set no-new-privileges. Remove them with
# `docker rm -f deb1 arch1`.
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
rm -f "$here/rootkey.pub"

start() {
    docker rm -f "$1" >/dev/null 2>&1 || true
    docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        --name "$1" --hostname "$1" -p "127.0.0.1:$3:22" "$2" >/dev/null
}
start deb1 sensible-test-debian 2211
start arch1 sensible-test-arch 2212

cp -r "$here/config/." "$work/config/"
cat > "$work/config/sensible.yml" <<YAML
secrets:
  recipients:
    - $recipient
  identity_command:
    - cat
    - $work/age.key
YAML
cat > "$work/config/hosts.yml" <<YAML
hosts:

  deb1:
    address: 127.0.0.1:2211
    roles:
      base:
      vim:
      sshd:
      zsh:
        prompt_colours:
          chris: yellow

  arch1:
    address: 127.0.0.1:2212
    roles:
      base:
      vim:
      sshd:
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
