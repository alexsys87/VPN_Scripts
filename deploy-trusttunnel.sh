#!/usr/bin/env bash
#
# deploy-trusttunnel.sh — one-command TrustTunnel endpoint deploy (AdGuard VPN
# protocol: HTTP/1.1 + HTTP/2 over TLS on TCP, HTTP/3 over QUIC on UDP),
# designed to run SIDE BY SIDE with an Xray VLESS+REALITY server installed by
# deploy-xray.sh.
#
# Installs the TrustTunnel endpoint, generates users/passwords and a TLS
# certificate, writes vpn.toml / hosts.toml / credentials.toml, a hardened
# systemd unit and firewall rules (TCP+UDP), runs an end-to-end self-test with
# the official CLI client (HTTP/2 and HTTP/3) and prints ready-to-use tt://
# deep links (also saved to <workdir>/links.txt).
#
# Usage:
#   bash deploy-trusttunnel.sh [options]
#
# Options:
#   --port PORT       listen port, TCP+UDP (default: 8443; 443/tcp belongs to Xray)
#   --ip IP           public IP to advertise in links (default: from Xray links, else autodetect)
#   --clients N       number of users to create (default: 3)
#   --name PREFIX     user/label prefix (default: tt)
#   --domain DOMAIN   use a Let's Encrypt cert for DOMAIN (certbot standalone, needs 80/tcp;
#                     DOMAIN must resolve to this server). Default: self-signed cert
#   --email EMAIL     ACME account e-mail for --domain (optional)
#   --hostname HOST   TLS hostname (SNI) for the self-signed cert (default: random www.<x>.com)
#   --cert FILE --key FILE
#                     use an existing certificate chain + private key instead
#   --dns UPSTREAM    DNS upstream put into client links (default: tls://1.1.1.1)
#   --archive FILE    use a local trusttunnel-*.tar.gz instead of downloading
#   --workdir DIR     where to store links.txt + backups (default: /root/trusttunnel-deploy)
#   --force           regenerate users/passwords/self-signed cert even if a config exists (reset)
#   --uninstall       remove TrustTunnel only (Xray, its firewall rule and its hardening stay)
#   --check           diagnose the running setup (incl. coexistence with Xray), no changes
#   --fix             diagnose, then auto-repair what is safely fixable (restart the service,
#                     re-apply hardening, re-open firewall ports, renew an expiring LE cert)
#                     and re-check; never rewrites configs or rotates passwords
#   --no-harden       skip network hardening (UDP buffers for QUIC / MTU probing / MSS clamp)
#   --skip-test       do not run the end-to-end client self-test
#   --dry-run         generate configs (+ links if the binary exists), do not touch the system
#   -h, --help        show this help
#
# Notes:
#   * Coexistence with Xray: the script reads /usr/local/etc/xray/config.json and refuses
#     a port Xray uses; it never edits Xray's config, unit, firewall rule, sysctl file or
#     MSS clamp. Every rule it adds is tagged with the comment "trusttunnel" and only
#     those rules are removed on --uninstall. Xray's health is checked before and after.
#   * Idempotent by default: re-running REUSES the existing users, passwords, hostname and
#     certificate, so client links stay valid. Use --force to rotate everything.
#   * Tested on Debian 11/12 and Ubuntu 20.04/22.04/24.04 (systemd), x86_64 / aarch64.
#   * Self-signed certs are embedded into the tt:// link (supported by the CLI client and
#     the current TrustTunnel apps). For maximum camouflage use --domain with a real domain.
#   * Anti-drop hardening (on by default, disable with --no-harden), same values as
#     deploy-xray.sh so the two files never conflict:
#       - large UDP socket buffers (QUIC/HTTP3 needs >= 7 MB);
#       - net.ipv4.tcp_mtu_probing=1 + BBR/fq, persisted in /etc/sysctl.d;
#       - MSS clamping, only if Xray's clamp is not already present.
#
set -euo pipefail

# ---------- defaults ----------
PORT="8443"
PUB_IP=""
NCLIENTS="3"
NAME="tt"
DOMAIN=""
EMAIL=""
TT_HOST=""
CERT_IN=""
KEY_IN=""
DNS_UP="tls://1.1.1.1"
ARCHIVE=""
WORKDIR="/root/trusttunnel-deploy"
INSTALL_DIR="/opt/trusttunnel"
DRY_RUN="0"
FORCE="0"
UNINSTALL="0"
CHECK="0"
FIX="0"
HARDEN="1"
SKIP_TEST="0"
PORT_SET="0"
TT_VERSION="${TT_VERSION:-1.3.1}"
TT_CLIENT_VERSION="${TT_CLIENT_VERSION:-1.3.0}"

XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_WORKDIR="/root/xray-deploy"
UNIT_FILE="/etc/systemd/system/trusttunnel.service"
SYSCTL_FILE="/etc/sysctl.d/99-trusttunnel-hardening.conf"
LE_HOOK="/etc/letsencrypt/renewal-hooks/deploy/trusttunnel.sh"
FW_TAG="trusttunnel"
FW_TAG_ACME="trusttunnel-acme"
SVC_USER="trusttunnel"
TT_BIN="$INSTALL_DIR/trusttunnel_endpoint"
STATE_FILE="$INSTALL_DIR/.deploy-state"

# ---------- helpers ----------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

TMPDIRS=()
cleanup_tmp() {
  local d
  if [ "${#TMPDIRS[@]}" -gt 0 ]; then
    for d in "${TMPDIRS[@]}"; do
      [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d" || true
    done
  fi
  return 0
}
mktmp() { local d; d="$(mktemp -d)"; TMPDIRS+=("$d"); printf '%s' "$d"; }
trap cleanup_tmp EXIT

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0; }

# ---------- parse args ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --port)      PORT="$2"; PORT_SET="1"; shift 2 ;;
    --ip)        PUB_IP="$2"; shift 2 ;;
    --clients)   NCLIENTS="$2"; shift 2 ;;
    --name)      NAME="$2"; shift 2 ;;
    --domain)    DOMAIN="$2"; shift 2 ;;
    --email)     EMAIL="$2"; shift 2 ;;
    --hostname)  TT_HOST="$2"; shift 2 ;;
    --cert)      CERT_IN="$2"; shift 2 ;;
    --key)       KEY_IN="$2"; shift 2 ;;
    --dns)       DNS_UP="$2"; shift 2 ;;
    --archive)   ARCHIVE="$2"; shift 2 ;;
    --workdir)   WORKDIR="$2"; shift 2 ;;
    --force)     FORCE="1"; shift ;;
    --uninstall) UNINSTALL="1"; shift ;;
    --check)     CHECK="1"; shift ;;
    --fix)       FIX="1"; shift ;;
    --no-harden) HARDEN="0"; shift ;;
    --skip-test) SKIP_TEST="1"; shift ;;
    --dry-run)   DRY_RUN="1"; shift ;;
    -h|--help)   usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
case "$NCLIENTS" in ''|*[!0-9]*) die "--clients must be a number" ;; esac
[ "$NCLIENTS" -ge 1 ] || die "--clients must be >= 1"
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port out of range"
case "$NAME" in ''|*[!A-Za-z0-9_-]*) die "--name may only contain A-Z a-z 0-9 _ -" ;; esac
if [ -n "$CERT_IN$KEY_IN" ]; then
  [ -n "$CERT_IN" ] && [ -n "$KEY_IN" ] || die "--cert and --key must be given together"
  [ -z "$DOMAIN" ] || die "--domain and --cert/--key are mutually exclusive"
  [ -n "$TT_HOST" ] || die "--cert/--key need --hostname (the name in the certificate)"
fi
[ -z "$EMAIL" ] || [ -n "$DOMAIN" ] || die "--email only makes sense with --domain"

CERT_MODE="self-signed"
[ -n "$DOMAIN" ] && { CERT_MODE="letsencrypt"; TT_HOST="$DOMAIN"; }
[ -n "$CERT_IN" ] && CERT_MODE="provided"

# state written by a previous install (port, cert mode, domain) — lets --check/--fix/
# --uninstall work without repeating the original options
load_state() {
  [ -f "$STATE_FILE" ] || return 1
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      PORT)      [ "$PORT_SET" = "1" ] || PORT="$v" ;;
      CERT_MODE) ST_CERT_MODE="$v" ;;
      DOMAIN)    ST_DOMAIN="$v" ;;
      HOST)      ST_HOST="$v" ;;
      WORKDIR)   ST_WORKDIR="$v" ;;
    esac
  done < "$STATE_FILE"
  return 0
}
ST_CERT_MODE=""; ST_DOMAIN=""; ST_HOST=""; ST_WORKDIR=""
load_state || true

# a plain re-run keeps the certificate mode of the previous install
if [ "$CERT_MODE" = "self-signed" ] && [ -z "$TT_HOST" ]; then
  case "$ST_CERT_MODE" in
    letsencrypt) [ -n "$ST_DOMAIN" ] && { CERT_MODE="letsencrypt"; DOMAIN="$ST_DOMAIN"; TT_HOST="$DOMAIN"; } ;;
    provided)    CERT_MODE="provided"; TT_HOST="$ST_HOST" ;;   # reuse the cert files in place
  esac
fi

# ---------- prerequisites ----------
ensure_prereqs() {
  local need=""
  command -v curl    >/dev/null 2>&1 || need="$need curl"
  command -v tar     >/dev/null 2>&1 || need="$need tar"
  command -v python3 >/dev/null 2>&1 || need="$need python3"
  command -v openssl >/dev/null 2>&1 || need="$need openssl"
  command -v ss      >/dev/null 2>&1 || need="$need iproute2"
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    command -v certbot >/dev/null 2>&1 || need="$need certbot"
  fi
  if [ -n "$need" ]; then
    log "installing prerequisites:$need"
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq $need ca-certificates
  fi
  # optional: terminal QR codes for the links
  if ! command -v qrencode >/dev/null 2>&1; then
    apt-get install -y -qq qrencode >/dev/null 2>&1 || true
  fi
}

# ---------- detect public IP ----------
detect_ip() {
  local ip u
  # 1) reuse what deploy-xray.sh advertised, so both VPNs point at the same address
  if [ -f "$XRAY_WORKDIR/links.txt" ]; then
    ip="$(sed -n '1s/^vless:\/\/[^@]*@\([^:]*\):.*/\1/p' "$XRAY_WORKDIR/links.txt" 2>/dev/null || true)"
    case "$ip" in *.*.*.*) echo "$ip"; return 0 ;; esac
  fi
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip="$(curl -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]')" || true
    case "$ip" in
      *[!0-9a-fA-F:.]*|"") continue ;;
      *.*|*:*) echo "$ip"; return 0 ;;
    esac
  done
  return 1
}

# ---------- Xray coexistence ----------
XRAY_PORTS=""
XRAY_WAS_ACTIVE="0"
xray_ports() {
  [ -f "$XRAY_CFG" ] || return 0
  python3 - "$XRAY_CFG" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for ib in d.get("inbounds", []):
        p = ib.get("port")
        if p is not None:
            print(p)
except Exception:
    pass
PY
}

xray_sni() {
  [ -f "$XRAY_CFG" ] || return 0
  python3 - "$XRAY_CFG" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0])
except Exception:
    pass
PY
}

# who listens on PORT (tcp or udp)? prints process names, empty if free
port_owners() {
  local proto="$1" port="$2" out
  out="$(ss -H "-l${proto}np" 2>/dev/null || true)"
  awk -v p=":$port" '$4 ~ p"$" || $5 ~ p"$"' <<<"$out" \
    | grep -o 'users:(("[^"]*"' | sed 's/users:(("//' | sort -u | tr '\n' ' ' || true
}

check_coexistence() {
  XRAY_PORTS="$(xray_ports | tr '\n' ' ')"
  if [ -n "$XRAY_PORTS" ]; then
    log "Xray detected (ports: ${XRAY_PORTS% }); TrustTunnel will not touch it"
    local p
    for p in $XRAY_PORTS; do
      [ "$p" = "$PORT" ] && die "port $PORT is used by Xray; pick another one with --port"
    done
  else
    log "no Xray config found at $XRAY_CFG (installing TrustTunnel alone)"
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray 2>/dev/null; then
    XRAY_WAS_ACTIVE="1"
  fi
  local o
  for proto in t u; do
    o="$(port_owners "$proto" "$PORT")"
    if [ -n "$o" ] && ! grep -q "trusttunnel" <<<"$o"; then
      die "port $PORT/$( [ $proto = t ] && echo tcp || echo udp) is busy ($o); pick another --port"
    fi
  done
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    o="$(port_owners t 80)"
    [ -z "$o" ] || die "port 80/tcp is busy ($o): certbot standalone needs it. Use --cert/--key instead"
  fi
}

# Xray must still be alive after we are done
verify_xray_alive() {
  [ "$XRAY_WAS_ACTIVE" = "1" ] || return 0
  if systemctl is-active --quiet xray 2>/dev/null; then
    log "Xray is still active (coexistence OK)"
  else
    warn "Xray was active before but is NOT active now: journalctl -u xray -n 50"
    return 1
  fi
}

# ---------- install / locate the endpoint ----------
tt_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "unsupported CPU $(uname -m) (TrustTunnel ships x86_64 and aarch64)" ;;
  esac
}

installed_version_ok() {
  [ -x "$TT_BIN" ] || return 1
  local v; v="$("$TT_BIN" --version 2>/dev/null || true)"
  grep -q "$TT_VERSION" <<<"$v"
}

install_tt() {
  mkdir -p "$INSTALL_DIR"
  if [ -z "$ARCHIVE" ] && installed_version_ok && [ "$FORCE" != "1" ]; then
    log "TrustTunnel endpoint v${TT_VERSION} already installed"
  else
    local tmp pkg dir arch
    arch="$(tt_arch)" || exit 1
    tmp="$(mktmp)"
    if [ -n "$ARCHIVE" ]; then
      [ -f "$ARCHIVE" ] || die "--archive $ARCHIVE not found"
      pkg="$ARCHIVE"
    else
      pkg="$tmp/tt.tar.gz"
      log "downloading TrustTunnel endpoint v${TT_VERSION} (${arch})"
      curl -fsSL -o "$pkg" \
        "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${TT_VERSION}/trusttunnel-v${TT_VERSION}-linux-${arch}.tar.gz"
    fi
    mkdir -p "$tmp/x"
    tar -xzf "$pkg" -C "$tmp/x"
    dir="$(dirname "$(find "$tmp/x" -type f -name trusttunnel_endpoint | head -n1)")"
    [ -f "$dir/trusttunnel_endpoint" ] || die "trusttunnel_endpoint not found in the archive"
    install -m 0755 "$dir/trusttunnel_endpoint" "$TT_BIN"
    [ -f "$dir/LICENSE" ] && install -m 0644 "$dir/LICENSE" "$INSTALL_DIR/LICENSE"
  fi
  "$TT_BIN" --version 2>/dev/null || true
}

ensure_user() {
  id "$SVC_USER" >/dev/null 2>&1 && return 0
  useradd --system --no-create-home --home-dir "$INSTALL_DIR" \
    --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || useradd -r -M -d "$INSTALL_DIR" -s /usr/sbin/nologin "$SVC_USER"
  log "created system user $SVC_USER"
}

# ---------- generators ----------
gen_password() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(24)))'; }
gen_hostname() { python3 -c 'import secrets,string;print("www."+"".join(secrets.choice(string.ascii_lowercase) for _ in range(9))+".com")'; }

ipv6_available() {
  ip -6 route get 2001:4860:4860::8888 >/dev/null 2>&1 && echo true || echo false
}

# ---------- reuse an existing install (idempotent re-run) ----------
EXIST_USERS=(); EXIST_PASSES=(); EXIST_HOST=""
load_existing() {
  local dir="$1"
  [ -f "$dir/credentials.toml" ] && [ -f "$dir/hosts.toml" ] || return 1
  local out
  out="$(python3 - "$dir/credentials.toml" "$dir/hosts.toml" <<'PY'
import re, sys
creds = open(sys.argv[1]).read()
hosts = open(sys.argv[2]).read()
m = re.search(r'^\s*hostname\s*=\s*"([^"]+)"', hosts, re.M)
print(m.group(1) if m else "")
for block in re.split(r'^\s*\[\[client\]\]\s*$', creds, flags=re.M)[1:]:
    u = re.search(r'^\s*username\s*=\s*"([^"]*)"', block, re.M)
    p = re.search(r'^\s*password\s*=\s*"([^"]*)"', block, re.M)
    if u and p:
        print(u.group(1) + "\t" + p.group(1))
PY
)" || return 1
  EXIST_HOST="$(printf '%s\n' "$out" | sed -n '1p')"
  local u p
  while IFS=$'\t' read -r u p; do
    [ -n "$u" ] || continue
    EXIST_USERS+=("$u"); EXIST_PASSES+=("$p")
  done < <(printf '%s\n' "$out" | sed -n '2,$p')
  [ "${#EXIST_USERS[@]}" -gt 0 ]
}

in_list() { local x="$1" e; shift; for e in "$@"; do [ "$e" = "$x" ] && return 0; done; return 1; }

# build USERS/PASSES: reuse existing ones (first N), add new ones up to N
build_users() {
  USERS=(); PASSES=()
  local i=0
  if [ "$FORCE" != "1" ] && [ "${#EXIST_USERS[@]}" -gt 0 ]; then
    for i in "${!EXIST_USERS[@]}"; do
      [ "${#USERS[@]}" -ge "$NCLIENTS" ] && break
      USERS+=("${EXIST_USERS[$i]}"); PASSES+=("${EXIST_PASSES[$i]}")
    done
  fi
  local n=$(( ${#USERS[@]} + 1 ))
  while [ "${#USERS[@]}" -lt "$NCLIENTS" ]; do
    local cand="${NAME}-${n}"
    # avoid clashing with a reused username
    while in_list "$cand" "${USERS[@]}"; do n=$((n+1)); cand="${NAME}-${n}"; done
    USERS+=("$cand"); PASSES+=("$(gen_password)")
    n=$((n+1))
  done
}

# ---------- certificates ----------
# result: CERT_PATH / KEY_PATH inside <dir>/certs
cert_selfsigned() {
  local dir="$1"
  local c="$dir/certs/cert.pem" k="$dir/certs/key.pem"
  mkdir -p "$dir/certs"
  if [ "$FORCE" != "1" ] && [ -f "$c" ] && [ -f "$k" ] \
     && openssl x509 -in "$c" -noout -checkend 2592000 >/dev/null 2>&1 \
     && openssl x509 -in "$c" -noout -text 2>/dev/null | grep -q "DNS:${TT_HOST}"; then
    log "reusing self-signed certificate for $TT_HOST"
  else
    log "generating self-signed certificate for $TT_HOST (ECDSA P-256, 10 years)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$k" -out "$c" -days 3650 -subj "/CN=${TT_HOST}" \
      -addext "subjectAltName=DNS:${TT_HOST}" >/dev/null 2>&1 \
      || die "openssl failed to create a self-signed certificate"
  fi
  CERT_PATH="$c"; KEY_PATH="$k"
}

cert_provided() {
  local dir="$1"
  if [ -z "$CERT_IN" ]; then   # re-run: keep the previously provided files
    [ -f "$dir/certs/cert.pem" ] && [ -f "$dir/certs/key.pem" ] \
      || die "previous install used --cert/--key but the files are gone; pass them again"
    CERT_PATH="$dir/certs/cert.pem"; KEY_PATH="$dir/certs/key.pem"
    log "reusing provided certificate for $TT_HOST"
    return 0
  fi
  [ -r "$CERT_IN" ] && [ -r "$KEY_IN" ] || die "cannot read --cert/--key"
  mkdir -p "$dir/certs"
  install -m 0640 "$CERT_IN" "$dir/certs/cert.pem"
  install -m 0640 "$KEY_IN"  "$dir/certs/key.pem"
  CERT_PATH="$dir/certs/cert.pem"; KEY_PATH="$dir/certs/key.pem"
  log "using provided certificate for $TT_HOST"
}

# certbot keeps the files in /etc/letsencrypt (root-only); a deploy hook copies them
# into $INSTALL_DIR/certs for the unprivileged service and reloads it (SIGHUP).
write_le_hook() {
  mkdir -p "$(dirname "$LE_HOOK")"
  cat > "$LE_HOOK" <<EOF
#!/bin/sh
# installed by deploy-trusttunnel.sh — copies the renewed cert for TrustTunnel
[ "\${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/${DOMAIN}" ] || exit 0
install -m 0640 -o root -g ${SVC_USER} "\$RENEWED_LINEAGE/fullchain.pem" ${INSTALL_DIR}/certs/cert.pem
install -m 0640 -o root -g ${SVC_USER} "\$RENEWED_LINEAGE/privkey.pem"   ${INSTALL_DIR}/certs/key.pem
systemctl reload trusttunnel >/dev/null 2>&1 || systemctl restart trusttunnel >/dev/null 2>&1 || true
EOF
  chmod 0755 "$LE_HOOK"
}

cert_letsencrypt() {
  local dir="$1"
  # verify DNS first: a wrong A record is the #1 reason for ACME failures
  local resolved
  resolved="$(python3 -c 'import socket,sys
try: print(" ".join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)})))
except Exception: print("")' "$DOMAIN")"
  if ! grep -qw -- "$PUB_IP" <<<"$resolved"; then
    die "$DOMAIN resolves to '${resolved:-nothing}', not $PUB_IP — fix the A record first"
  fi
  open_acme_port
  local acct=(--register-unsafely-without-email)
  [ -n "$EMAIL" ] && acct=(-m "$EMAIL")
  log "requesting Let's Encrypt certificate for $DOMAIN (certbot standalone on :80)"
  certbot certonly --standalone --non-interactive --agree-tos "${acct[@]}" \
    --keep-until-expiring --key-type ecdsa -d "$DOMAIN" >/dev/null \
    || die "certbot failed for $DOMAIN (is 80/tcp reachable from the Internet?)"
  write_le_hook
  mkdir -p "$dir/certs"
  install -m 0640 "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$dir/certs/cert.pem"
  install -m 0640 "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$dir/certs/key.pem"
  CERT_PATH="$dir/certs/cert.pem"; KEY_PATH="$dir/certs/key.pem"
  log "certificate installed; auto-renewal via certbot.timer + $LE_HOOK"
}

# ---------- write configs ----------
write_configs() {
  local dir="$1"
  python3 - "$dir" "$PORT" "$TT_HOST" "$CERT_PATH" "$KEY_PATH" "$(ipv6_available)" \
           "${#USERS[@]}" "${USERS[@]}" "${PASSES[@]}" <<'PY'
import os, sys
d, port, host, cert, key, v6, n = sys.argv[1:8]
n = int(n)
users = sys.argv[8:8+n]
passes = sys.argv[8+n:8+2*n]
creds = os.path.join(d, "credentials.toml")

vpn = f'''# generated by deploy-trusttunnel.sh — see CONFIGURATION.md of TrustTunnel
listen_address = "0.0.0.0:{port}"
ipv6_available = {v6}
allow_private_network_connections = false
credentials_file = "{creds}"
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
auth_failure_status_code = 407

# HTTP/1.1 + HTTP/2 on TCP {port}, HTTP/3 (QUIC) on UDP {port}
[listen_protocols.http1]

[listen_protocols.http2]

[listen_protocols.quic]
'''
hosts = f'''[[main_hosts]]
hostname = "{host}"
cert_chain_path = "{cert}"
private_key_path = "{key}"
'''
c = "".join(f'[[client]]\nusername = "{u}"\npassword = "{p}"\n\n' for u, p in zip(users, passes))
for name, body in (("vpn.toml", vpn), ("hosts.toml", hosts), ("credentials.toml", c)):
    with open(os.path.join(d, name), "w") as f:
        f.write(body)
print(f"  wrote {d}/vpn.toml, hosts.toml, credentials.toml ({n} users)")
PY
}

fix_perms() {
  chown root:"$SVC_USER" "$INSTALL_DIR" "$INSTALL_DIR"/*.toml "$INSTALL_DIR/certs" "$INSTALL_DIR"/certs/* 2>/dev/null || true
  chmod 0750 "$INSTALL_DIR" "$INSTALL_DIR/certs"
  chmod 0640 "$INSTALL_DIR"/*.toml "$INSTALL_DIR"/certs/*
  chmod 0755 "$TT_BIN"
}

write_state() {
  cat > "$STATE_FILE" <<EOF
PORT=$PORT
CERT_MODE=$CERT_MODE
DOMAIN=$DOMAIN
HOST=$TT_HOST
WORKDIR=$WORKDIR
EOF
  chmod 0600 "$STATE_FILE"
}

# ---------- systemd unit ----------
write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=TrustTunnel endpoint
Documentation=https://github.com/TrustTunnel/TrustTunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${TT_BIN} ${INSTALL_DIR}/vpn.toml ${INSTALL_DIR}/hosts.toml
# SIGHUP reloads TLS hosts (used by the Let's Encrypt renewal hook)
ExecReload=/bin/kill -HUP \$MAINPID
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

# ---------- firewall (tagged rules only) ----------
nft_input_target() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list chains 2>/dev/null | awk '
    /^table / { fam=$2; tbl=$3 }
    /^[[:space:]]*chain / { chain=$2 }
    /hook input/ { if (!done) { print fam, tbl, chain; done=1 } }
  '
}

persist_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list ruleset > /etc/nftables.conf 2>/dev/null || return 0
  command -v systemctl >/dev/null 2>&1 && systemctl enable nftables >/dev/null 2>&1 || true
  log "nft: ruleset saved to /etc/nftables.conf"
}

save_iptables() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

# fw_allow PROTO PORT TAG
fw_allow() {
  local proto="$1" port="$2" tag="$3" done_any=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
    ufw allow "${port}/${proto}" comment "$tag" >/dev/null 2>&1 || ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    log "ufw: allowed ${port}/${proto}"
    done_any=1
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$tag" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p "$proto" --dport "$port" -m comment --comment "$tag" -j ACCEPT
    if save_iptables; then log "iptables: allowed ${proto}/${port} (saved)"
    else log "iptables: allowed ${proto}/${port} (not persisted; install iptables-persistent)"; fi
    done_any=1
  fi
  if [ "$done_any" = "0" ] && command -v nft >/dev/null 2>&1; then
    local tgt fam="" tbl="" chain=""
    tgt="$(nft_input_target)"
    [ -n "$tgt" ] && read -r fam tbl chain <<<"$tgt" || true
    if [ -z "$fam" ]; then
      nft add table inet filter 2>/dev/null || true
      nft add chain inet filter input '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true
      fam=inet; tbl=filter; chain=input
    fi
    local rules; rules="$(nft list chain "$fam" "$tbl" "$chain" 2>/dev/null || true)"
    if grep -Eq "${proto} dport ${port} .*comment \"${tag}\"" <<<"$rules"; then
      log "nft: ${proto}/${port} already allowed in $fam/$tbl/$chain"
    elif nft add rule "$fam" "$tbl" "$chain" "$proto" dport "$port" accept comment "\"$tag\"" 2>/dev/null; then
      log "nft: allowed ${proto}/${port} in $fam/$tbl/$chain"
    else
      warn "nft: failed to add rule for ${proto}/${port}"
    fi
    persist_nft
  fi
}

open_firewall() {
  fw_allow tcp "$PORT" "$FW_TAG"
  fw_allow udp "$PORT" "$FW_TAG"
}

open_acme_port() { fw_allow tcp 80 "$FW_TAG_ACME"; }

# remove only rules tagged by this script, from every backend present
remove_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
    ufw delete allow "${PORT}/udp" >/dev/null 2>&1 || true
    [ "${ST_CERT_MODE:-$CERT_MODE}" = "letsencrypt" ] && ufw delete allow 80/tcp >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null 2>&1; then
    local line rules
    rules="$(iptables -S INPUT 2>/dev/null || true)"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      local -a args
      read -ra args <<<"${line/-A INPUT/-D INPUT}"
      iptables "${args[@]}" >/dev/null 2>&1 || true
    done < <(grep -E -- "--comment \"?(${FW_TAG}|${FW_TAG_ACME})\"?( |$)" <<<"$rules" || true)
    save_iptables || true
  fi
  if command -v nft >/dev/null 2>&1; then
    local fam="" tbl="" chain="" h
    while read -r fam tbl chain h; do
      [ -n "$h" ] && nft delete rule "$fam" "$tbl" "$chain" handle "$h" 2>/dev/null || true
    done < <(nft -a list ruleset 2>/dev/null | awk -v t1="\"$FW_TAG\"" -v t2="\"$FW_TAG_ACME\"" '
      /^table / { fam=$2; tbl=$3 }
      /^[[:space:]]*chain / { chain=$2 }
      /comment/ && (index($0, "comment " t1) || index($0, "comment " t2)) {
        for (i=1;i<=NF;i++) if ($i=="handle") print fam, tbl, chain, $(i+1)
      }')
    persist_nft
  fi
}

# ---------- network hardening ----------
apply_sysctl() {
  local k v kv changed=0
  local tmp; tmp="$(mktmp)/sysctl.conf"
  : > "$tmp"
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    [ "$(sysctl -n "$k" 2>/dev/null)" != "$v" ] && changed=1
    printf '%s=%s\n' "$k" "$v" >> "$tmp"
  done
  if [ -f "$SYSCTL_FILE" ] && cmp -s "$tmp" "$SYSCTL_FILE"; then
    log "sysctl: hardening already in place ($SYSCTL_FILE)"
  else
    cp "$tmp" "$SYSCTL_FILE"
    log "sysctl: wrote $SYSCTL_FILE"
  fi
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || \
    while read -r line; do [ -n "$line" ] && sysctl -w "$line" >/dev/null 2>&1 || true; done < "$SYSCTL_FILE"
  [ "$changed" = "1" ] && log "sysctl: applied (udp buffers, mtu_probing, bbr)"
  return 0
}

mss_clamp_present() {
  local m n
  m="$(iptables -t mangle -S 2>/dev/null || true)"
  n="$(nft list ruleset 2>/dev/null || true)"
  grep -q "clamp-mss-to-pmtu" <<<"$m" || grep -qE "clamp-mss-to-pmtu|maxseg size set" <<<"$n"
}

harden_network() {
  [ "$HARDEN" = "1" ] || { log "hardening skipped (--no-harden)"; return 0; }
  log "hardening network (values identical to deploy-xray.sh, no conflicts)"
  # rmem/wmem: QUIC/HTTP3 needs big UDP socket buffers; the TCP knobs match Xray's file
  apply_sysctl \
    "net.core.rmem_max=16777216" \
    "net.core.wmem_max=16777216" \
    "net.ipv4.tcp_mtu_probing=1" \
    "net.ipv4.tcp_base_mss=1024" \
    "net.ipv4.tcp_slow_start_after_idle=0" \
    "net.core.default_qdisc=fq" \
    "net.ipv4.tcp_congestion_control=bbr"
  if mss_clamp_present; then
    log "mss: clamp already present (shared with Xray), nothing to add"
  elif command -v iptables >/dev/null 2>&1 && \
       iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
         -m comment --comment "$FW_TAG" -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
    save_iptables || true
    log "mss: clamp-to-pmtu enabled (iptables mangle, tagged $FW_TAG)"
  elif command -v nft >/dev/null 2>&1; then
    nft add table inet trusttunnel-harden 2>/dev/null || true
    nft add chain inet trusttunnel-harden post '{ type filter hook postrouting priority mangle ; policy accept ; }' 2>/dev/null || true
    if nft add rule inet trusttunnel-harden post tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null; then
      persist_nft; log "mss: clamp-to-pmtu enabled (nft table inet trusttunnel-harden)"
    else
      warn "mss: failed to add nft clamp"
    fi
  else
    warn "mss: no iptables/nft backend; skipped clamp"
  fi
  return 0
}

# remove only OUR hardening; Xray's /etc/sysctl.d/99-xray-hardening.conf and clamp stay
unharden_network() {
  if [ -f "$SYSCTL_FILE" ]; then
    rm -f "$SYSCTL_FILE"
    log "sysctl: removed $SYSCTL_FILE (runtime values kept; Xray's file still applies on boot)"
  fi
  if command -v iptables >/dev/null 2>&1; then
    while iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment "$FW_TAG" -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; do
      iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -m comment --comment "$FW_TAG" -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || break
    done
    save_iptables || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet trusttunnel-harden 2>/dev/null || true
  fi
  return 0
}

# ---------- links ----------
export_link() {   # export_link USER LABEL ADDRESS -> prints tt:// link
  local out
  out="$(cd "$1" && "$TT_BIN" "$1/vpn.toml" "$1/hosts.toml" -c "$2" -a "$4" \
          --name "$3" --dns-upstream "$DNS_UP" --format deeplink 2>/dev/null)" || return 1
  grep -m1 -o '^tt://[^[:space:]]*' <<<"$out"
}

write_links() {
  local dir="$1" out="$WORKDIR/links.txt" i=0 u link label
  : > "$out"
  for u in "${USERS[@]}"; do
    i=$((i+1))
    label="${u}@${PUB_IP}"
    link="$(export_link "$dir" "$u" "$label" "${PUB_IP}:${PORT}")" \
      || die "endpoint rejected the generated config (export for $u failed)"
    printf '%s\n' "$link" >> "$out"
  done
  log "links saved to $out"
}

# ---------- CLI client config (Linux/macOS/Windows trusttunnel_client) ----------
write_client_config() {   # write_client_config OUT LISTENER(tun|socks:ADDR) PROTO ADDRESS
  local out="$1" listener="$2" proto="$3" addr="$4" cert_pem="" subj iss
  # a self-signed cert must be pinned in the client; a CA-issued one uses the system store
  if [ -f "${CERT_PATH:-}" ]; then
    subj="$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
    iss="$(openssl x509 -in "$CERT_PATH" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')"
    [ -n "$subj" ] && [ "$subj" = "$iss" ] && cert_pem="$(cat "$CERT_PATH")"
  fi
  python3 - "$out" "$listener" "$proto" "$addr" "$TT_HOST" "${USERS[0]}" "${PASSES[0]}" \
           "$cert_pem" "$DNS_UP" "$(ipv6_available)" <<'PY'
import sys
out, listener, proto, addr, host, user, pw, cert, dns, v6 = sys.argv[1:11]
lines = [
  'loglevel = "info"', 'vpn_mode = "general"',
  f'killswitch_enabled = {"true" if listener == "tun" else "false"}',
  'exclusions = []', '', '[endpoint]',
  f'hostname = "{host}"', f'addresses = ["{addr}"]', f'has_ipv6 = {v6}',
  f'username = "{user}"', f'password = "{pw}"',
  'skip_verification = false',
  f'certificate = """\n{cert.strip()}\n"""' if cert else 'certificate = ""',
  f'upstream_protocol = "{proto}"', 'anti_dpi = false',
  f'dns_upstreams = ["{dns}"]', '',
]
if listener == "tun":
    lines += ['[listener.tun]', 'bound_if = ""',
              'included_routes = ["0.0.0.0/0", "2000::/3"]',
              'excluded_routes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]',
              'mtu_size = 1350', 'change_system_dns = true']
else:
    lines += ['[listener.socks]', f'address = "{listener.split(":",1)[1]}"']
open(out, "w").write("\n".join(lines) + "\n")
PY
}

# ---------- diagnostics (--check) ----------
check_setup() {
  set +e
  log "diagnosing TrustTunnel setup (read-only)"
  local issues=0 cfgdir="$INSTALL_DIR"

  if systemctl is-active --quiet trusttunnel 2>/dev/null; then
    log "  [OK] trusttunnel service active"
  else
    warn "  [!!] trusttunnel service is NOT active"; issues=$((issues+1))
  fi

  local first_user=""
  if [ -f "$cfgdir/vpn.toml" ] && [ -f "$cfgdir/hosts.toml" ] && [ -f "$cfgdir/credentials.toml" ]; then
    log "  [OK] configs present in $cfgdir"
    first_user="$(sed -n 's/^username = "\(.*\)"$/\1/p' "$cfgdir/credentials.toml" | head -n1)"
    if [ -x "$TT_BIN" ] && [ -n "$first_user" ] && \
       (cd "$cfgdir" && "$TT_BIN" vpn.toml hosts.toml -c "$first_user" -a "127.0.0.1:$PORT" --format toml >/dev/null 2>&1); then
      log "  [OK] endpoint parses the configs (client export works)"
    else
      warn "  [!!] endpoint FAILS to parse configs/certs"; issues=$((issues+1))
    fi
  else
    warn "  [!!] configs missing in $cfgdir"; issues=$((issues+1))
  fi

  # listening on TCP and UDP
  local proto o
  for proto in t u; do
    o="$(port_owners "$proto" "$PORT")"
    local pn; pn="$( [ $proto = t ] && echo tcp || echo udp)"
    if grep -q trusttunnel <<<"$o"; then log "  [OK] listening on ${pn}/${PORT}"
    elif [ -n "$o" ]; then warn "  [!!] ${pn}/${PORT} is taken by: $o"; issues=$((issues+1))
    else warn "  [!!] nothing listens on ${pn}/${PORT}"; issues=$((issues+1)); fi
  done

  # coexistence with Xray
  local xp; xp="$(xray_ports | tr '\n' ' ')"
  if [ -n "$xp" ]; then
    if grep -qw "$PORT" <<<"$xp"; then
      warn "  [!!] port $PORT is ALSO configured in Xray ($xp)"; issues=$((issues+1))
    fi
    if systemctl is-active --quiet xray 2>/dev/null; then
      log "  [OK] Xray active alongside (ports: ${xp% })"
    else
      warn "  [!!] Xray is installed but NOT active -> run: bash deploy-xray.sh --fix"
      issues=$((issues+1))
    fi
  else
    log "  [--] Xray not installed"
  fi

  # TLS handshake on the endpoint
  local host; host="$(sed -n 's/^hostname = "\(.*\)"$/\1/p' "$cfgdir/hosts.toml" 2>/dev/null | head -n1)"
  if [ -n "$host" ] && command -v openssl >/dev/null 2>&1; then
    local hs; hs="$(timeout 8 openssl s_client -connect "127.0.0.1:$PORT" -servername "$host" \
                     -alpn h2 </dev/null 2>/dev/null || true)"
    if grep -q "^Server certificate\|BEGIN CERTIFICATE" <<<"$hs"; then
      log "  [OK] TLS handshake on tcp/${PORT} (SNI $host)"
    else
      warn "  [!!] TLS handshake on tcp/${PORT} failed"; issues=$((issues+1))
    fi
  fi

  # certificate expiry
  local crt="$cfgdir/certs/cert.pem"
  if [ -f "$crt" ]; then
    if openssl x509 -in "$crt" -noout -checkend 1209600 >/dev/null 2>&1; then
      log "  [OK] certificate valid until $(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)"
    else
      warn "  [!!] certificate expires within 14 days (or already expired)"; issues=$((issues+1))
    fi
  fi
  if [ "${ST_CERT_MODE}" = "letsencrypt" ]; then
    if [ -x "$LE_HOOK" ]; then log "  [OK] LE renewal hook present"
    else warn "  [!!] LE renewal hook missing ($LE_HOOK)"; issues=$((issues+1)); fi
  fi

  # firewall
  local ufw_out ipt_out nft_out
  ufw_out="$(ufw status 2>/dev/null || true)"
  ipt_out="$(iptables -S INPUT 2>/dev/null || true)"
  nft_out="$(nft list ruleset 2>/dev/null || true)"
  for pn in tcp udp; do
    local ok=0
    grep -q "^${PORT}/${pn}" <<<"$ufw_out" && ok=1
    grep -qE -- "-p ${pn} .*--dport ${PORT} .*-j ACCEPT" <<<"$ipt_out" && ok=1
    grep -qE "${pn} dport ${PORT} .*accept" <<<"$nft_out" && ok=1
    if [ "$ok" = "1" ]; then log "  [OK] firewall allows ${pn}/${PORT}"
    else warn "  [!!] no firewall rule for ${pn}/${PORT}"; issues=$((issues+1)); fi
  done

  # kernel knobs
  local rmax mp
  rmax="$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)"
  if [ "${rmax:-0}" -ge 7340032 ] 2>/dev/null; then log "  [OK] net.core.rmem_max=$rmax (enough for QUIC)"
  else warn "  [!!] net.core.rmem_max=$rmax (QUIC/HTTP3 may drop packets)"; issues=$((issues+1)); fi
  mp="$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo '?')"
  if [ "$mp" = "1" ]; then log "  [OK] tcp_mtu_probing=1"
  else warn "  [!!] tcp_mtu_probing=$mp"; issues=$((issues+1)); fi
  if mss_clamp_present; then log "  [OK] MSS clamp present"
  else warn "  [!!] no MSS clamp (PPPoE/PMTU-blackhole clients may fail)"; issues=$((issues+1)); fi

  # errors since the last start
  if systemctl is-active --quiet trusttunnel 2>/dev/null; then
    local since errs
    since="$(systemctl show -p ActiveEnterTimestamp --value trusttunnel 2>/dev/null)"
    errs="$(journalctl -u trusttunnel --since "$since" --no-pager 2>/dev/null | grep -ciE '\bERROR\b|panicked' || true)"
    if [ "${errs:-0}" -gt 0 ]; then
      log "  [--] ${errs} error line(s) in the journal since last start (scanners/bad auth also count):"
      log "       journalctl -u trusttunnel -n 50"
    else
      log "  [OK] no errors in the journal since last start"
    fi
  fi

  echo
  if [ "$issues" -eq 0 ]; then log "check: no problems found"; return 0; fi
  warn "check: $issues issue(s) found (see above)"
  return 1
}

# ---------- auto-repair (--fix) ----------
fix_setup() {
  set +e
  log "auto-repair (--fix): diagnosing first"
  check_setup
  [ $? -eq 0 ] && { log "nothing to fix"; return 0; }
  log "applying repairs"

  if [ -x "$TT_BIN" ] && [ -f "$UNIT_FILE" ] && ! systemctl is-active --quiet trusttunnel 2>/dev/null; then
    warn "  -> trusttunnel not active; restarting"
    fix_perms
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart trusttunnel >/dev/null 2>&1 || true
    sleep 3
    systemctl is-active --quiet trusttunnel 2>/dev/null && log "  [fixed] trusttunnel restarted" \
      || warn "  [!!] trusttunnel still down: journalctl -u trusttunnel -n 50"
  fi

  if [ "$ST_CERT_MODE" = "letsencrypt" ] && [ -n "$ST_DOMAIN" ] && \
     ! openssl x509 -in "$INSTALL_DIR/certs/cert.pem" -noout -checkend 1209600 >/dev/null 2>&1; then
    warn "  -> renewing Let's Encrypt certificate for $ST_DOMAIN"
    DOMAIN="$ST_DOMAIN"; write_le_hook
    fw_allow tcp 80 "$FW_TAG_ACME"
    certbot renew --cert-name "$ST_DOMAIN" --force-renewal --non-interactive >/dev/null 2>&1 \
      && log "  [fixed] certificate renewed" || warn "  [!!] certbot renew failed"
  elif [ "$ST_CERT_MODE" = "self-signed" ] && \
       ! openssl x509 -in "$INSTALL_DIR/certs/cert.pem" -noout -checkend 1209600 >/dev/null 2>&1; then
    warn "  -> self-signed cert expiring: re-run with --force to issue a new one (links change)"
  fi

  HARDEN="1"; harden_network
  open_firewall

  echo
  log "re-checking after repairs"
  check_setup
  local rc2=$?
  [ "$rc2" -eq 0 ] && log "fix: all problems resolved" || warn "fix: some issues remain, see output above"
  return "$rc2"
}

# ---------- uninstall ----------
uninstall() {
  [ -n "$ST_WORKDIR" ] && WORKDIR="$ST_WORKDIR"
  log "uninstalling TrustTunnel (port $PORT, workdir $WORKDIR) — Xray is left untouched"
  local xray_active=0
  systemctl is-active --quiet xray 2>/dev/null && xray_active=1

  systemctl stop trusttunnel >/dev/null 2>&1 || true
  systemctl disable trusttunnel >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed trusttunnel >/dev/null 2>&1 || true

  remove_firewall
  unharden_network

  if [ -f "$LE_HOOK" ]; then
    rm -f "$LE_HOOK"
    log "removed LE deploy hook; the certificate itself stays (certbot delete --cert-name ${ST_DOMAIN:-<domain>})"
  fi

  rm -rf "$INSTALL_DIR" "$WORKDIR"
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" >/dev/null 2>&1 || true
  cleanup_tmp

  log "done. verifying leftovers:"
  local left="" p
  for p in "$INSTALL_DIR" "$UNIT_FILE" "$WORKDIR" "$SYSCTL_FILE" "$LE_HOOK"; do
    [ -e "$p" ] && left="$left $p"
  done
  systemctl is-active --quiet trusttunnel 2>/dev/null && left="$left (service still active)"
  if iptables -S 2>/dev/null | grep -q -- "--comment \"\?${FW_TAG}"; then left="$left (iptables rules)"; fi
  if [ "$xray_active" = "1" ]; then
    if systemctl is-active --quiet xray 2>/dev/null; then log "Xray still active (untouched)"
    else warn "Xray was active before uninstall but is not now: journalctl -u xray -n 50"; fi
  fi
  if [ -n "$left" ]; then warn "leftovers remain:$left"; return 1; fi
  log "no leftovers found"
  return 0
}

# ---------- E2E self-test with the official CLI client (HTTP/2 and HTTP/3) ----------
CLIENT_BIN=""
fetch_client() {
  local tmp; tmp="$(mktmp)"
  log "downloading TrustTunnel CLI client v${TT_CLIENT_VERSION} for the self-test"
  curl -fsSL -o "$tmp/c.tar.gz" \
    "https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v${TT_CLIENT_VERSION}/trusttunnel_client-v${TT_CLIENT_VERSION}-linux-$(tt_arch).tar.gz" \
    || return 1
  tar -xzf "$tmp/c.tar.gz" -C "$tmp" || return 1
  CLIENT_BIN="$(find "$tmp" -type f -name trusttunnel_client | head -n1)"
  [ -n "$CLIENT_BIN" ] && chmod +x "$CLIENT_BIN"
}

self_test_one() {   # self_test_one http2|http3 SOCKSPORT
  local proto="$1" sp="$2" tdir got="" pid
  tdir="$(mktmp)"
  write_client_config "$tdir/c.toml" "socks:127.0.0.1:${sp}" "$proto" "127.0.0.1:${PORT}"
  setsid "$CLIENT_BIN" --config "$tdir/c.toml" </dev/null >"$tdir/c.log" 2>&1 &
  pid=$!
  sleep 4
  for _ in 1 2 3 4; do
    got="$(curl -s --max-time 20 --socks5-hostname "127.0.0.1:${sp}" https://api.ipify.org 2>/dev/null || true)"
    [ -n "$got" ] && break
    sleep 3
  done
  kill "$pid" 2>/dev/null || true
  sleep 1; kill -9 "$pid" 2>/dev/null || true
  if [ "$got" = "$PUB_IP" ]; then
    log "self-test ${proto} OK (egress IP = $got)"
    return 0
  fi
  warn "self-test ${proto} FAILED (got '${got:-empty}', expected $PUB_IP); client log:"
  tail -n 15 "$tdir/c.log" >&2 || true
  return 1
}

self_test() {
  log "end-to-end self-test"
  if ! fetch_client; then
    warn "could not download the CLI client; skipping the tunnel test (use --skip-test to silence)"
    return 0
  fi
  local rc=0
  self_test_one http2 10890 || rc=1
  self_test_one http3 10891 || { warn "HTTP/3 failed: check that udp/${PORT} is open at your provider"; rc=1; }
  return "$rc"
}

# ---------- backup / rollback ----------
BACKUP=""
backup_existing() {
  [ -f "$INSTALL_DIR/vpn.toml" ] || return 0
  BACKUP="$WORKDIR/backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP"
  cp -a "$INSTALL_DIR"/*.toml "$BACKUP"/ 2>/dev/null || true
  [ -d "$INSTALL_DIR/certs" ] && cp -a "$INSTALL_DIR/certs" "$BACKUP"/ || true
  log "backed up existing config to $BACKUP"
}

rollback() {
  if [ -n "$BACKUP" ] && [ -d "$BACKUP" ]; then
    cp -a "$BACKUP"/*.toml "$INSTALL_DIR"/ 2>/dev/null || true
    [ -d "$BACKUP/certs" ] && cp -a "$BACKUP/certs/." "$INSTALL_DIR/certs/" || true
    fix_perms
    systemctl restart trusttunnel >/dev/null 2>&1 || true
    warn "restored previous config from $BACKUP and restarted trusttunnel"
  else
    warn "no previous config to restore; leaving generated config in place"
  fi
}

# =====================================================================
#  main
# =====================================================================
if [ "$UNINSTALL" = "1" ]; then uninstall; exit $?; fi
if [ "$CHECK" = "1" ]; then check_setup; exit $?; fi
if [ "$FIX" = "1" ]; then fix_setup; exit $?; fi

[ "$DRY_RUN" = "1" ] || ensure_prereqs
if [ -z "$PUB_IP" ]; then
  PUB_IP="$(detect_ip)" || die "cannot detect public IP; pass --ip"
fi
mkdir -p "$WORKDIR"
umask 077

# hostname: --domain > existing install > --hostname > random
if load_existing "$INSTALL_DIR" && [ "$FORCE" != "1" ]; then
  if [ "$CERT_MODE" = "self-signed" ] && [ -z "$TT_HOST" ]; then
    TT_HOST="$EXIST_HOST"
  fi
  REUSE="1"
else
  REUSE="0"
fi
[ -n "$TT_HOST" ] || TT_HOST="$(gen_hostname)"

log "public IP: $PUB_IP   port: $PORT (tcp+udp)   host: $TT_HOST   cert: $CERT_MODE   users: $NCLIENTS"

if [ "$DRY_RUN" = "1" ]; then
  log "DRY RUN: no system changes"
  D="$WORKDIR/dry-run"; mkdir -p "$D"
  build_users
  case "$CERT_MODE" in
    provided) cert_provided "$D" ;;
    letsencrypt) mkdir -p "$D/certs"; CERT_PATH="$D/certs/cert.pem"; KEY_PATH="$D/certs/key.pem"
                 warn "dry-run: Let's Encrypt not requested, cert paths are placeholders" ;;
    *) cert_selfsigned "$D" ;;
  esac
  write_configs "$D"
  write_client_config "$WORKDIR/client.toml" tun http2 "${PUB_IP}:${PORT}"
  if [ -x "$TT_BIN" ] && [ "$CERT_MODE" != "letsencrypt" ]; then
    write_links "$D"; echo "--- links ---"; cat "$WORKDIR/links.txt"
  else
    log "endpoint binary not installed: links are generated only on a real run"
  fi
  echo "--- configs: $D/{vpn,hosts,credentials}.toml ; client: $WORKDIR/client.toml ---"
  exit 0
fi

check_coexistence
install_tt
ensure_user

if [ "$REUSE" = "1" ]; then
  log "existing install found: reusing ${#EXIST_USERS[@]} user(s), hostname and certificate"
  log "(run with --force to rotate passwords/cert and issue new links)"
fi
build_users
backup_existing

case "$CERT_MODE" in
  provided)    cert_provided "$INSTALL_DIR" ;;
  letsencrypt) cert_letsencrypt "$INSTALL_DIR" ;;
  *)           cert_selfsigned "$INSTALL_DIR" ;;
esac

write_configs "$INSTALL_DIR"
fix_perms
write_state

# the endpoint has no -test mode: exporting a client config parses every file
(cd "$INSTALL_DIR" && "$TT_BIN" vpn.toml hosts.toml -c "${USERS[0]}" -a "${PUB_IP}:${PORT}" --format toml >/dev/null) \
  || { rollback; die "generated config rejected by trusttunnel_endpoint"; }
log "config valid"

write_unit
systemctl daemon-reload
systemctl enable trusttunnel >/dev/null 2>&1 || true
systemctl restart trusttunnel
sleep 3
if ! systemctl is-active --quiet trusttunnel; then
  rollback
  die "trusttunnel did not start; see: journalctl -u trusttunnel -n 50"
fi
log "trusttunnel active on tcp+udp/${PORT}"

open_firewall
harden_network
write_links "$INSTALL_DIR"
write_client_config "$WORKDIR/client.toml" tun http2 "${PUB_IP}:${PORT}"
log "CLI client config written to $WORKDIR/client.toml"

if [ "$SKIP_TEST" != "1" ] && ! self_test; then
  warn "config is installed but the tunnel self-test failed."
  rollback
  verify_xray_alive || true
  warn "Inspect: journalctl -u trusttunnel -n 50"
  exit 2
fi
verify_xray_alive || warn "TrustTunnel is up, but check Xray: bash deploy-xray.sh --check"

echo
log "DONE. TrustTunnel links (import into the TrustTunnel app / scan as QR):"
cat "$WORKDIR/links.txt"
if command -v qrencode >/dev/null 2>&1; then
  echo; log "QR for ${USERS[0]}:"
  qrencode -t ANSIUTF8 "$(head -n1 "$WORKDIR/links.txt")" || true
fi
echo
log "users (username / password):"
for i in "${!USERS[@]}"; do printf '    %s / %s\n' "${USERS[$i]}" "${PASSES[$i]}"; done
log "endpoint: ${PUB_IP}:${PORT} tcp+udp   hostname (SNI): $TT_HOST   cert: $CERT_MODE"
log "configs: $INSTALL_DIR/{vpn,hosts,credentials}.toml   links: $WORKDIR/links.txt"
log "CLI client: trusttunnel_client --config $WORKDIR/client.toml"
[ "$HARDEN" = "1" ] && log "hardening: $SYSCTL_FILE"
[ -n "$XRAY_PORTS" ] && log "Xray untouched on port(s): ${XRAY_PORTS% }"
exit 0
