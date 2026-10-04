#!/bin/bash
# Runs inside a node container, as root, called by INSTALL/node_install.py.
#
#   setup.sh base                       runtime: python venv, pinned dependencies
#   setup.sh orchestrator <listen-ip>   Orchestrator service on its bridge address
#   setup.sh portal <orchestrator-url>  broker, Participant files, operator commands
#
# Safe to re-run. Existing Participant registry and access policy are kept.
set -euo pipefail

APP=/opt/civic-orchestrator
CURRENT="$APP/current"
VENV="$APP/venv"
ETC=/etc/civic-orchestrator
SYSTEMD_SRC="$CURRENT/INSTALL/systemd"

log() { printf '   [%s] %s\n' "$(hostname)" "$*"; }
die() { printf '   [%s] ERROR: %s\n' "$(hostname)" "$*" >&2; exit 1; }

render() {
  # render TEMPLATE DEST NAME=VALUE...
  local template="$1" dest="$2"; shift 2
  local content
  content="$(cat "$template")"
  for pair in "$@"; do
    content="${content//@${pair%%=*}@/${pair#*=}}"
  done
  if grep -q '@[A-Z_]*@' <<<"$content"; then
    die "unrendered placeholder in $template"
  fi
  printf '%s\n' "$content" > "$dest.tmp"
  chmod 0644 "$dest.tmp"
  mv -f "$dest.tmp" "$dest"
}

stage_base() {
  export DEBIAN_FRONTEND=noninteractive
  log "installing python3-venv"
  apt-get -o DPkg::Lock::Timeout=600 update -q >/dev/null
  apt-get -o DPkg::Lock::Timeout=600 install -y -q python3-venv curl >/dev/null

  [ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
  log "installing pinned dependencies (hash-verified)"
  "$VENV/bin/pip" install -q --disable-pip-version-check --require-hashes \
    -r "$CURRENT/INSTALL/requirements.lock"

  # Use the installed release in place: no build step, and switching
  # releases is a single symlink change.
  local site
  site="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
  printf '%s\n' "$CURRENT/src" > "$site/civic-orchestrator.pth"
  log "civic_orchestrator $("$VENV/bin/python" -c 'import civic_orchestrator as c; print(c.__version__)')"
}

stage_orchestrator() {
  local listen="${1:?listen address required}"
  [[ "$listen" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "invalid listen address: $listen"
  [ -s "$ETC/credentials/adapter.json" ] || die "adapter credential is missing"

  id civic-orchestrator >/dev/null 2>&1 || \
    useradd --system --home-dir /var/lib/civic-orchestrator --shell /usr/sbin/nologin civic-orchestrator
  install -d -m 0750 -o civic-orchestrator -g civic-orchestrator \
    /var/lib/civic-orchestrator /var/lib/civic-orchestrator/state

  render "$SYSTEMD_SRC/civic-orchestrator.service" /etc/systemd/system/civic-orchestrator.service \
    "ORCHESTRATOR_LISTEN=$listen"
  systemctl daemon-reload
  systemctl enable civic-orchestrator.service >/dev/null 2>&1
  systemctl restart civic-orchestrator.service

  for _ in $(seq 1 30); do
    if curl -fsS -m 2 "http://$listen:8045/healthz" >/dev/null 2>&1; then
      log "Orchestrator listening on $listen:8045"
      return 0
    fi
    sleep 1
  done
  systemctl --no-pager status civic-orchestrator.service | tail -20 >&2 || true
  die "Orchestrator did not become healthy"
}

stage_portal() {
  local orchestrator_url="${1:?orchestrator URL required}"

  getent group civic-participants >/dev/null || groupadd --system civic-participants
  id civic-broker >/dev/null 2>&1 || \
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin civic-broker

  install -d -m 0755 "$ETC"
  # Contracts and schemas the broker validates against: public, read-only.
  install -m 0644 "$CURRENT/contracts/custom-command-registry-v1.yaml" "$ETC/"
  install -m 0644 "$CURRENT/contracts/custom-command-help-v1.yaml" "$ETC/"
  install -m 0644 "$CURRENT/schemas/custom-command-registry-v1.schema.json" "$ETC/"
  install -m 0644 "$CURRENT/schemas/custom-command-help-v1.schema.json" "$ETC/"
  install -m 0644 "$CURRENT/schemas/custom-command-access-v1.schema.json" "$ETC/"

  # Participant registry and access policy: authorization data. Created empty
  # (default deny) on first install, never overwritten afterwards.
  "$VENV/bin/python" - "$ETC" <<'PY'
import json, sys, yaml
from pathlib import Path
from civic_orchestrator.participant_admin import empty_access_policy, empty_registry
etc = Path(sys.argv[1])
registry = etc / "participants-v1.json"
access = etc / "custom-command-access-v1.yaml"
if not registry.exists():
    registry.write_text(json.dumps(empty_registry(), indent=2) + "\n")
if not access.exists():
    access.write_text(yaml.safe_dump(empty_access_policy(), sort_keys=False))
PY
  chown root:civic-broker "$ETC/participants-v1.json" "$ETC/custom-command-access-v1.yaml"
  chmod 0640 "$ETC/participants-v1.json" "$ETC/custom-command-access-v1.yaml"

  printf 'CIVIC_ORCHESTRATOR_BASE_URL=%s\n' "$orchestrator_url" > "$ETC/node.env"
  chmod 0644 "$ETC/node.env"

  install -m 0644 "$SYSTEMD_SRC/civic-custom-command-broker.socket" /etc/systemd/system/
  install -m 0644 "$SYSTEMD_SRC/civic-custom-command-broker.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now civic-custom-command-broker.socket >/dev/null 2>&1
  systemctl try-restart civic-custom-command-broker.service

  cat > /usr/local/sbin/civic-participant <<EOF
#!/bin/sh
exec $VENV/bin/python -m civic_orchestrator.participant_admin "\$@"
EOF
  cat > /usr/local/sbin/civic-transport-check <<EOF
#!/bin/sh
. $ETC/node.env
exec $VENV/bin/python -m civic_orchestrator.transport_check \\
  --orchestrator-base-url "\$CIVIC_ORCHESTRATOR_BASE_URL" "\$@"
EOF
  chmod 0755 /usr/local/sbin/civic-participant /usr/local/sbin/civic-transport-check

  # Probe the broker exactly as a client would. root is not a Participant,
  # so a well-formed refusal proves the broker is alive and enforcing.
  "$VENV/bin/python" - <<'PY'
import json, socket, struct, sys
meta = json.dumps({"protocol_version": 2, "request_kind": "list",
                   "codename": None, "arguments": {}}).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(10)
    s.connect("/run/civic-orchestrator/custom-command.sock")
    s.sendall(struct.pack("!II", len(meta), 0) + meta)
    head = s.recv(4)
    body = b""
    (length,) = struct.unpack("!I", head)
    while len(body) < length:
        body += s.recv(length - len(body))
reply = json.loads(body)
if reply.get("status") not in {"ok", "rejected"} or reply.get("remote_dispatch") is not False:
    sys.exit(f"unexpected broker reply: {reply}")
print("   broker answered:", reply.get("status"), "-", reply.get("error", "ok"))
PY
  log "Portal ready: broker socket /run/civic-orchestrator/custom-command.sock"
}

stage="${1:?stage required: base | orchestrator | portal}"
shift
case "$stage" in
  base) stage_base "$@" ;;
  orchestrator) stage_orchestrator "$@" ;;
  portal) stage_portal "$@" ;;
  *) die "unknown stage: $stage" ;;
esac
