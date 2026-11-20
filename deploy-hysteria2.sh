#!/usr/bin/env bash
#
# deploy-hysteria2.sh — one-command Hysteria2 deploy (QUIC/UDP, HTTP/3 masquerade),
# designed to run SIDE BY SIDE with Xray VLESS+REALITY (deploy-xray.sh, TCP 443)
# and TrustTunnel (deploy-trusttunnel.sh, TCP+UDP 8443).
#
# Installs Hysteria2, generates users/passwords and a TLS certificate, writes a
# hardened config, a systemd unit and firewall rules (UDP), optionally sets up
# UDP port hopping, runs an end-to-end self-test with the hysteria binary in
# client mode and prints ready-to-use hysteria2:// links (also saved to
# <workdir>/links.txt).
#
# Usage:
#   bash deploy-hysteria2.sh [options]
#
# Options:
#   --port PORT       UDP listen port (default: 443 — free, Xray only uses TCP 443)
#   --ip IP           public IP to advertise (default: from Xray links, else autodetect)
#   --clients N       number of users to create (default: 3)
#   --name PREFIX     user/label prefix (default: hy2)
#   --domain DOMAIN   Let's Encrypt cert for DOMAIN (certbot standalone on 80/tcp;
#                     may be the same domain TrustTunnel uses). Default: self-signed
#   --email EMAIL     ACME account e-mail for --domain (optional)
#   --hostname HOST   SNI / name in the self-signed cert (default: Xray's mask domain,
#                     else www.bing.com)
#   --cert FILE --key FILE
#                     use an existing certificate chain + private key
#   --masq URL        site proxied for non-Hysteria HTTP/3 visitors
#                     (default: https://<hostname>/ for self-signed, https://www.bing.com/ otherwise)
#   --obfs            enable Salamander obfuscation (hides QUIC entirely, but disables
#                     the HTTP/3 masquerade and needs a client that supports it)
#   --hop RANGE       UDP port hopping, e.g. 20000-50000 (iptables/nft REDIRECT to PORT)
#   --bin PATH        use a local hysteria binary instead of downloading
#   --workdir DIR     where to store links.txt + backups (default: /root/hysteria2-deploy)
#   --force           regenerate users/passwords/obfs key/self-signed cert (reset)
#   --uninstall       remove Hysteria2 only (Xray and TrustTunnel stay untouched)
#   --check           diagnose the running setup (incl. a live tunnel test and the
#                     health of Xray/TrustTunnel), no changes
#   --fix             diagnose, then auto-repair what is safely fixable (restart the service,
#                     re-apply hardening, firewall and port hopping, renew an expiring LE
#                     cert) and re-check; never rewrites the config or rotates passwords
#   --no-harden       skip network hardening (UDP buffers / MTU probing / MSS clamp)
#   --skip-test       do not run the end-to-end self-test
#   --dry-run         generate config + links, do not touch the system
#   -h, --help        show this help
#
# Notes:
#   * Coexistence: Xray's ports (from /usr/local/etc/xray/config.json) and TrustTunnel's
#     port (from /opt/trusttunnel/.deploy-state) are refused, the hop range may not cover
#     any listening UDP port, and the masquerade never listens on TCP (TCP 443 is Xray's).
#     Every rule added here is tagged "hysteria" and only those are removed on --uninstall.
#   * Idempotent by default: re-running REUSES users, passwords, obfs key, hostname and
#     certificate, so links stay valid. Use --force to rotate everything.
#   * Self-signed certs are pinned in the link (insecure=1 + pinSHA256), so the client
#     still verifies the server. Clients without pinSHA256 support fall back to insecure.
#   * Hardening uses the same sysctl values as the other two scripts (no conflicts).
#   * Tested on Debian 11/12 and Ubuntu 20.04/22.04/24.04 (systemd), amd64 / arm64.
#
set -euo pipefail

# ---------- defaults ----------
PORT="443"
PUB_IP=""
NCLIENTS="3"
NAME="hy2"
DOMAIN=""
EMAIL=""
HY_HOST=""
CERT_IN=""
KEY_IN=""
MASQ=""
OBFS="0"
HOP=""
XBIN=""
WORKDIR="/root/hysteria2-deploy"
DRY_RUN="0"
FORCE="0"
UNINSTALL="0"
CHECK="0"
FIX="0"
HARDEN="1"
SKIP_TEST="0"
PORT_SET="0"
HOP_SET="0"
HY_VERSION="${HY_VERSION:-2.14.0}"

HY_BIN="/usr/local/bin/hysteria"
CONF_DIR="/etc/hysteria"
CFG="$CONF_DIR/config.yaml"
STATE_FILE="$CONF_DIR/.deploy-state"
UNIT_NAME="hysteria-server"
UNIT_FILE="/etc/systemd/system/${UNIT_NAME}.service"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-hardening.conf"
LE_HOOK="/etc/letsencrypt/renewal-hooks/deploy/hysteria.sh"
SVC_USER="hysteria"
FW_TAG="hysteria"
FW_TAG_ACME="hysteria-acme"
FW_TAG_HOP="hysteria-hop"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_WORKDIR="/root/xray-deploy"
TT_STATE="/opt/trusttunnel/.deploy-state"

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
in_list() { local x="$1" e; shift; for e in "$@"; do [ "$e" = "$x" ] && return 0; done; return 1; }

# ---------- parse args ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --port)      PORT="$2"; PORT_SET="1"; shift 2 ;;
    --ip)        PUB_IP="$2"; shift 2 ;;
    --clients)   NCLIENTS="$2"; shift 2 ;;
    --name)      NAME="$2"; shift 2 ;;
    --domain)    DOMAIN="$2"; shift 2 ;;
    --email)     EMAIL="$2"; shift 2 ;;
    --hostname)  HY_HOST="$2"; shift 2 ;;
    --cert)      CERT_IN="$2"; shift 2 ;;
    --key)       KEY_IN="$2"; shift 2 ;;
    --masq)      MASQ="$2"; shift 2 ;;
    --obfs)      OBFS="1"; shift ;;
    --hop)       HOP="$2"; HOP_SET="1"; shift 2 ;;
    --bin)       XBIN="$2"; shift 2 ;;
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
if [ -n "$HOP" ]; then
  case "$HOP" in *[!0-9-]*|*-*-*|-*|*-) die "--hop must look like 20000-50000" ;; esac
  case "$HOP" in *-*) ;; *) die "--hop must look like 20000-50000" ;; esac
  HOP_LO="${HOP%-*}"; HOP_HI="${HOP#*-}"
  [ "$HOP_LO" -ge 1024 ] && [ "$HOP_HI" -le 65535 ] && [ "$HOP_LO" -lt "$HOP_HI" ] \
    || die "--hop range must be within 1024-65535 and LOW < HIGH"
fi
if [ -n "$CERT_IN$KEY_IN" ]; then
  [ -n "$CERT_IN" ] && [ -n "$KEY_IN" ] || die "--cert and --key must be given together"
  [ -z "$DOMAIN" ] || die "--domain and --cert/--key are mutually exclusive"
  [ -n "$HY_HOST" ] || die "--cert/--key need --hostname (the name in the certificate)"
fi
[ -z "$EMAIL" ] || [ -n "$DOMAIN" ] || die "--email only makes sense with --domain"

CERT_MODE="self-signed"
[ -n "$DOMAIN" ] && { CERT_MODE="letsencrypt"; HY_HOST="$DOMAIN"; }
[ -n "$CERT_IN" ] && CERT_MODE="provided"

# ---------- state of a previous install ----------
ST_CERT_MODE=""; ST_DOMAIN=""; ST_HOST=""; ST_WORKDIR=""; ST_HOP=""; ST_OBFS=""; ST_MASQ=""
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
      HOP)       ST_HOP="$v" ;;
      OBFS)      ST_OBFS="$v" ;;
      MASQ)      ST_MASQ="$v" ;;
    esac
  done < "$STATE_FILE"
  return 0
}
load_state || true

# a plain re-run keeps the previous choices (cert mode, hop range, obfs, masquerade)
if [ "$CERT_MODE" = "self-signed" ] && [ -z "$HY_HOST" ]; then
  case "$ST_CERT_MODE" in
    letsencrypt) [ -n "$ST_DOMAIN" ] && { CERT_MODE="letsencrypt"; DOMAIN="$ST_DOMAIN"; HY_HOST="$DOMAIN"; } ;;
    provided)    CERT_MODE="provided"; HY_HOST="$ST_HOST" ;;
    self-signed) HY_HOST="$ST_HOST" ;;
  esac
fi
if [ "$HOP_SET" = "0" ] && [ -n "$ST_HOP" ]; then HOP="$ST_HOP"; HOP_LO="${HOP%-*}"; HOP_HI="${HOP#*-}"; fi
[ "$OBFS" = "0" ] && [ "$ST_OBFS" = "1" ] && OBFS="1"
[ -z "$MASQ" ] && [ -n "$ST_MASQ" ] && MASQ="$ST_MASQ"

# ---------- prerequisites ----------
ensure_prereqs() {
  local need=""
  command -v curl    >/dev/null 2>&1 || need="$need curl"
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
  command -v qrencode >/dev/null 2>&1 || apt-get install -y -qq qrencode >/dev/null 2>&1 || true
}

# ---------- detect public IP ----------
detect_ip() {
  local ip u
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

# ---------- coexistence with Xray / TrustTunnel ----------
xray_ports() {
  [ -f "$XRAY_CFG" ] || return 0
  python3 - "$XRAY_CFG" <<'PY' 2>/dev/null || true
import json, sys
try:
    for ib in json.load(open(sys.argv[1])).get("inbounds", []):
        if ib.get("port") is not None:
            print(ib["port"])
except Exception:
    pass
PY
}
xray_sni() {
  [ -f "$XRAY_CFG" ] || return 0
  python3 - "$XRAY_CFG" <<'PY' 2>/dev/null || true
import json, sys
try:
    print(json.load(open(sys.argv[1]))["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0])
except Exception:
    pass
PY
}
tt_port() { [ -f "$TT_STATE" ] && sed -n 's/^PORT=//p' "$TT_STATE" | head -n1 || true; }

port_owners() {   # port_owners t|u PORT -> process names listening there
  local out
  out="$(ss -H "-l${1}np" 2>/dev/null || true)"
  awk -v p=":$2" '$4 ~ p"$"' <<<"$out" \
    | grep -o 'users:(("[^"]*"' | sed 's/users:(("//' | sort -u | tr '\n' ' ' || true
}

XRAY_PORTS=""; TT_PORT=""; XRAY_WAS_ACTIVE="0"; TT_WAS_ACTIVE="0"
check_coexistence() {
  XRAY_PORTS="$(xray_ports | tr '\n' ' ')"
  TT_PORT="$(tt_port)"
  [ -n "$XRAY_PORTS" ] && log "Xray detected (tcp ports: ${XRAY_PORTS% }) — will not be touched"
  [ -n "$TT_PORT" ]    && log "TrustTunnel detected (tcp+udp port: $TT_PORT) — will not be touched"
  systemctl is-active --quiet xray 2>/dev/null && XRAY_WAS_ACTIVE="1"
  systemctl is-active --quiet trusttunnel 2>/dev/null && TT_WAS_ACTIVE="1"

  [ -n "$TT_PORT" ] && [ "$TT_PORT" = "$PORT" ] && die "udp/$PORT belongs to TrustTunnel; pick another --port"
  local o; o="$(port_owners u "$PORT")"
  if [ -n "$o" ] && ! grep -q "hysteria" <<<"$o"; then
    die "udp/$PORT is busy ($o); pick another --port"
  fi
  if [ -n "$HOP" ]; then
    [ "$PORT" -ge "$HOP_LO" ] && [ "$PORT" -le "$HOP_HI" ] && die "--hop range must not include the listen port $PORT"
    if [ -n "$TT_PORT" ] && [ "$TT_PORT" -ge "$HOP_LO" ] && [ "$TT_PORT" -le "$HOP_HI" ]; then
      die "--hop $HOP covers TrustTunnel's udp/$TT_PORT; choose another range"
    fi
    # no listening UDP socket may fall into the range (it would be hijacked by REDIRECT)
    local busy
    busy="$(ss -H -lun 2>/dev/null | awk -v lo="$HOP_LO" -v hi="$HOP_HI" '
      { n=split($4,a,":"); p=a[n]+0; if (p>=lo && p<=hi) print p }' | sort -un | tr '\n' ' ' || true)"
    [ -z "$busy" ] || die "--hop $HOP covers listening UDP port(s): $busy"
  fi
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    o="$(port_owners t 80)"
    [ -z "$o" ] || die "port 80/tcp is busy ($o): certbot standalone needs it. Use --cert/--key instead"
  fi
}

verify_neighbours() {
  local rc=0
  if [ "$XRAY_WAS_ACTIVE" = "1" ]; then
    if systemctl is-active --quiet xray 2>/dev/null; then log "Xray still active (untouched)"
    else warn "Xray was active but is NOT now: journalctl -u xray -n 50"; rc=1; fi
  fi
  if [ "$TT_WAS_ACTIVE" = "1" ]; then
    if systemctl is-active --quiet trusttunnel 2>/dev/null; then log "TrustTunnel still active (untouched)"
    else warn "TrustTunnel was active but is NOT now: journalctl -u trusttunnel -n 50"; rc=1; fi
  fi
  return "$rc"
}

# ---------- install hysteria ----------
hy_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "unsupported CPU $(uname -m)" ;;
  esac
}

install_hy() {
  if [ -n "$XBIN" ]; then
    [ -x "$XBIN" ] || die "--bin $XBIN is not executable"
    install -m 0755 "$XBIN" "$HY_BIN"
  elif [ -x "$HY_BIN" ] && "$HY_BIN" version 2>/dev/null | grep -q "v${HY_VERSION}" && [ "$FORCE" != "1" ]; then
    log "Hysteria v${HY_VERSION} already installed"
  else
    local arch tmp
    arch="$(hy_arch)" || exit 1
    tmp="$(mktmp)"
    log "downloading Hysteria v${HY_VERSION} (${arch})"
    curl -fsSL -o "$tmp/hysteria" \
      "https://github.com/apernet/hysteria/releases/download/app/v${HY_VERSION}/hysteria-linux-${arch}"
    install -m 0755 "$tmp/hysteria" "$HY_BIN"
  fi
  "$HY_BIN" version 2>/dev/null | grep -i '^version' || true
}

ensure_user() {
  id "$SVC_USER" >/dev/null 2>&1 && return 0
  useradd --system --no-create-home --home-dir /var/lib/hysteria \
    --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || useradd -r -M -d /var/lib/hysteria -s /usr/sbin/nologin "$SVC_USER"
  log "created system user $SVC_USER"
}

# ---------- generators ----------
gen_secret() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(24)))'; }

# ---------- reuse existing config ----------
EXIST_USERS=(); EXIST_PASSES=(); EXIST_OBFS_PW=""
load_existing() {
  [ -f "$CFG" ] || return 1
  local out u p
  out="$(python3 - "$CFG" <<'PY'
import json, re, sys
t = open(sys.argv[1]).read()
m = re.search(r'^obfs:.*?^\s+password:\s*(".*?")\s*$', t, re.S | re.M)
print(json.loads(m.group(1)) if m else "")
blk = re.search(r'^\s+userpass:\s*\n((?:\s{4,}".*\n)+)', t, re.M)
if blk:
    for line in blk.group(1).splitlines():
        mm = re.match(r'\s+(".*?")\s*:\s*(".*?")\s*$', line)
        if mm:
            print(json.loads(mm.group(1)) + "\t" + json.loads(mm.group(2)))
PY
)" || return 1
  EXIST_OBFS_PW="$(printf '%s\n' "$out" | sed -n '1p')"
  while IFS=$'\t' read -r u p; do
    [ -n "$u" ] || continue
    EXIST_USERS+=("$u"); EXIST_PASSES+=("$p")
  done < <(printf '%s\n' "$out" | sed -n '2,$p')
  [ "${#EXIST_USERS[@]}" -gt 0 ]
}

build_users() {
  USERS=(); PASSES=()
  local i
  if [ "$FORCE" != "1" ] && [ "${#EXIST_USERS[@]}" -gt 0 ]; then
    for i in "${!EXIST_USERS[@]}"; do
      [ "${#USERS[@]}" -ge "$NCLIENTS" ] && break
      USERS+=("${EXIST_USERS[$i]}"); PASSES+=("${EXIST_PASSES[$i]}")
    done
  fi
  local n=$(( ${#USERS[@]} + 1 )) cand
  while [ "${#USERS[@]}" -lt "$NCLIENTS" ]; do
    cand="${NAME}-${n}"
    while in_list "$cand" "${USERS[@]}"; do n=$((n+1)); cand="${NAME}-${n}"; done
    USERS+=("$cand"); PASSES+=("$(gen_secret)")
    n=$((n+1))
  done
  OBFS_PW=""
  if [ "$OBFS" = "1" ]; then
    if [ "$FORCE" != "1" ] && [ -n "$EXIST_OBFS_PW" ]; then OBFS_PW="$EXIST_OBFS_PW"; else OBFS_PW="$(gen_secret)"; fi
  fi
}

# ---------- certificates ----------
cert_selfsigned() {
  local dir="$1" c k
  c="$dir/cert.pem"; k="$dir/key.pem"
  mkdir -p "$dir"
  if [ "$FORCE" != "1" ] && [ -f "$c" ] && [ -f "$k" ] \
     && openssl x509 -in "$c" -noout -checkend 2592000 >/dev/null 2>&1 \
     && openssl x509 -in "$c" -noout -text 2>/dev/null | grep -q "DNS:${HY_HOST}"; then
    log "reusing self-signed certificate for $HY_HOST"
  else
    log "generating self-signed certificate for $HY_HOST (ECDSA P-256, 10 years)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$k" -out "$c" -days 3650 -subj "/CN=${HY_HOST}" \
      -addext "subjectAltName=DNS:${HY_HOST}" >/dev/null 2>&1 \
      || die "openssl failed to create a self-signed certificate"
  fi
  CERT_PATH="$c"; KEY_PATH="$k"
}

cert_provided() {
  local dir="$1"
  mkdir -p "$dir"
  if [ -z "$CERT_IN" ]; then
    [ -f "$dir/cert.pem" ] && [ -f "$dir/key.pem" ] \
      || die "previous install used --cert/--key but the files are gone; pass them again"
    log "reusing provided certificate for $HY_HOST"
  else
    [ -r "$CERT_IN" ] && [ -r "$KEY_IN" ] || die "cannot read --cert/--key"
    install -m 0640 "$CERT_IN" "$dir/cert.pem"
    install -m 0640 "$KEY_IN"  "$dir/key.pem"
    log "using provided certificate for $HY_HOST"
  fi
  CERT_PATH="$dir/cert.pem"; KEY_PATH="$dir/key.pem"
}

write_le_hook() {
  mkdir -p "$(dirname "$LE_HOOK")"
  cat > "$LE_HOOK" <<EOF
#!/bin/sh
# installed by deploy-hysteria2.sh — copies the renewed cert for Hysteria2
[ "\${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/${DOMAIN}" ] || exit 0
install -m 0640 -o root -g ${SVC_USER} "\$RENEWED_LINEAGE/fullchain.pem" ${CONF_DIR}/certs/cert.pem
install -m 0640 -o root -g ${SVC_USER} "\$RENEWED_LINEAGE/privkey.pem"   ${CONF_DIR}/certs/key.pem
systemctl restart ${UNIT_NAME} >/dev/null 2>&1 || true
EOF
  chmod 0755 "$LE_HOOK"
}

cert_letsencrypt() {
  local dir="$1" resolved
  resolved="$(python3 -c 'import socket,sys
try: print(" ".join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)})))
except Exception: print("")' "$DOMAIN")"
  grep -qw -- "$PUB_IP" <<<"$resolved" \
    || die "$DOMAIN resolves to '${resolved:-nothing}', not $PUB_IP — fix the A record first"
  fw_allow tcp 80 "$FW_TAG_ACME"
  local acct=(--register-unsafely-without-email)
  [ -n "$EMAIL" ] && acct=(-m "$EMAIL")
  log "requesting Let's Encrypt certificate for $DOMAIN (certbot standalone on :80)"
  certbot certonly --standalone --non-interactive --agree-tos "${acct[@]}" \
    --keep-until-expiring --key-type ecdsa -d "$DOMAIN" >/dev/null \
    || die "certbot failed for $DOMAIN (is 80/tcp reachable from the Internet?)"
  write_le_hook
  mkdir -p "$dir"
  install -m 0640 "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$dir/cert.pem"
  install -m 0640 "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$dir/key.pem"
  CERT_PATH="$dir/cert.pem"; KEY_PATH="$dir/key.pem"
  log "certificate installed; auto-renewal via certbot.timer + $LE_HOOK"
}

is_self_signed() {   # true if the leaf is self-signed (needs pinning in the client)
  local s i
  s="$(openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
  i="$(openssl x509 -in "$1" -noout -issuer  -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')"
  [ -n "$s" ] && [ "$s" = "$i" ]
}
cert_pin() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }

# ---------- write config ----------
write_config() {
  local out="$1"
  python3 - "$out" "$PORT" "$CERT_PATH" "$KEY_PATH" "$MASQ" "$OBFS_PW" \
           "${#USERS[@]}" "${USERS[@]}" "${PASSES[@]}" <<'PY'
import json, sys
out, port, cert, key, masq, obfs_pw, n = sys.argv[1:8]
n = int(n); users = sys.argv[8:8+n]; passes = sys.argv[8+n:8+2*n]
q = json.dumps   # JSON strings are valid YAML double-quoted scalars
L = ["# generated by deploy-hysteria2.sh",
     f"listen: {q(':' + port)}", "",
     "tls:", f"  cert: {q(cert)}", f"  key: {q(key)}", ""]
if obfs_pw:
    L += ["obfs:", "  type: salamander", "  salamander:", f"    password: {q(obfs_pw)}", ""]
L += ["auth:", "  type: userpass", "  userpass:"]
L += [f"    {q(u)}: {q(p)}" for u, p in zip(users, passes)]
L += ["",
      "quic:",
      "  initStreamReceiveWindow: 8388608",
      "  maxStreamReceiveWindow: 8388608",
      "  initConnReceiveWindow: 20971520",
      "  maxConnReceiveWindow: 20971520",
      "  maxIdleTimeout: 30s",
      "  maxIncomingStreams: 1024",
      "",
      "ignoreClientBandwidth: false",
      "",
      # block the server's private/loopback networks (explicit CIDRs: no geoip download)
      "acl:",
      "  inline:"] + [f"    - reject({c})" for c in (
          "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
          "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")] + [""]
if not obfs_pw:
    # HTTP/3 visitors that are not Hysteria clients see this site.
    # No listenHTTP/listenHTTPS: TCP 443 belongs to Xray.
    L += ["masquerade:", "  type: proxy", "  proxy:", f"    url: {q(masq)}", "    rewriteHost: true", ""]
open(out, "w").write("\n".join(L))
print(f"  wrote {out} ({n} users{', salamander obfs' if obfs_pw else ''})")
PY
}

fix_perms() {
  chown root:"$SVC_USER" "$CONF_DIR" "$CFG" "$CONF_DIR/certs" "$CONF_DIR"/certs/* 2>/dev/null || true
  chmod 0750 "$CONF_DIR" "$CONF_DIR/certs"
  chmod 0640 "$CFG" "$CONF_DIR"/certs/*
}

write_state() {
  cat > "$STATE_FILE" <<EOF
PORT=$PORT
CERT_MODE=$CERT_MODE
DOMAIN=$DOMAIN
HOST=$HY_HOST
WORKDIR=$WORKDIR
HOP=$HOP
OBFS=$OBFS
MASQ=$MASQ
EOF
  chmod 0600 "$STATE_FILE"
}

# ---------- systemd unit ----------
write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Hysteria2 Server
Documentation=https://v2.hysteria.network/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
StateDirectory=hysteria
WorkingDirectory=/var/lib/hysteria
Environment=HYSTERIA_LOG_LEVEL=warn
ExecStart=${HY_BIN} server --disable-update-check -c ${CFG}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
Restart=on-failure
RestartSec=5s
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
    /hook input/ { if (!done) { print fam, tbl, chain; done=1 } }'
}
persist_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list ruleset > /etc/nftables.conf 2>/dev/null || return 0
  systemctl enable nftables >/dev/null 2>&1 || true
  log "nft: ruleset saved to /etc/nftables.conf"
}
save_iptables() {
  command -v netfilter-persistent >/dev/null 2>&1 || return 1
  netfilter-persistent save >/dev/null 2>&1 || true
}

fw_allow() {   # fw_allow PROTO PORT TAG
  local proto="$1" port="$2" tag="$3" done_any=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
    ufw allow "${port}/${proto}" comment "$tag" >/dev/null 2>&1 || ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    log "ufw: allowed ${port}/${proto}"; done_any=1
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$tag" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p "$proto" --dport "$port" -m comment --comment "$tag" -j ACCEPT
    if save_iptables; then log "iptables: allowed ${proto}/${port} (saved)"
    else log "iptables: allowed ${proto}/${port} (not persisted; install iptables-persistent)"; fi
    done_any=1
  fi
  if [ "$done_any" = "0" ] && command -v nft >/dev/null 2>&1; then
    local tgt fam="" tbl="" chain="" rules
    tgt="$(nft_input_target)"
    [ -n "$tgt" ] && read -r fam tbl chain <<<"$tgt" || true
    if [ -z "$fam" ]; then
      nft add table inet filter 2>/dev/null || true
      nft add chain inet filter input '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true
      fam=inet; tbl=filter; chain=input
    fi
    rules="$(nft list chain "$fam" "$tbl" "$chain" 2>/dev/null || true)"
    if grep -Eq "${proto} dport ${port} .*comment \"${tag}\"" <<<"$rules"; then
      log "nft: ${proto}/${port} already allowed"
    elif nft add rule "$fam" "$tbl" "$chain" "$proto" dport "$port" accept comment "\"$tag\"" 2>/dev/null; then
      log "nft: allowed ${proto}/${port} in $fam/$tbl/$chain"
    else
      warn "nft: failed to add rule for ${proto}/${port}"
    fi
    persist_nft
  fi
}

open_firewall() { fw_allow udp "$PORT" "$FW_TAG"; }

# UDP port hopping: client picks ports in HOP range, the kernel redirects them to PORT
apply_hop() {
  [ -n "$HOP" ] || return 0
  if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -C PREROUTING -p udp --dport "${HOP_LO}:${HOP_HI}" -m comment --comment "$FW_TAG_HOP" \
      -j REDIRECT --to-ports "$PORT" >/dev/null 2>&1 || \
    iptables -t nat -A PREROUTING -p udp --dport "${HOP_LO}:${HOP_HI}" -m comment --comment "$FW_TAG_HOP" \
      -j REDIRECT --to-ports "$PORT"
    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -t nat -C PREROUTING -p udp --dport "${HOP_LO}:${HOP_HI}" -m comment --comment "$FW_TAG_HOP" \
        -j REDIRECT --to-ports "$PORT" >/dev/null 2>&1 || \
      ip6tables -t nat -A PREROUTING -p udp --dport "${HOP_LO}:${HOP_HI}" -m comment --comment "$FW_TAG_HOP" \
        -j REDIRECT --to-ports "$PORT" >/dev/null 2>&1 || true
    fi
    save_iptables || true
    log "port hopping: udp ${HOP} -> ${PORT} (iptables nat)"
  elif command -v nft >/dev/null 2>&1; then
    nft add table inet hysteria-hop 2>/dev/null || true
    nft add chain inet hysteria-hop prerouting '{ type nat hook prerouting priority dstnat ; policy accept ; }' 2>/dev/null || true
    if ! nft list chain inet hysteria-hop prerouting 2>/dev/null | grep -q "dport ${HOP_LO}-${HOP_HI}"; then
      nft add rule inet hysteria-hop prerouting udp dport "${HOP_LO}-${HOP_HI}" redirect to ":${PORT}" \
        || warn "nft: failed to add port hopping rule"
    fi
    persist_nft
    log "port hopping: udp ${HOP} -> ${PORT} (nft table inet hysteria-hop)"
  else
    warn "port hopping: no iptables/nft backend; skipped"
  fi
}

hop_present() {
  [ -n "$HOP" ] || return 0
  local a b
  a="$(iptables -t nat -S PREROUTING 2>/dev/null || true)"
  b="$(nft list table inet hysteria-hop 2>/dev/null || true)"
  grep -q -- "--comment \"\?${FW_TAG_HOP}" <<<"$a" || grep -q "dport ${HOP_LO}-${HOP_HI}" <<<"$b"
}

remove_firewall() {
  local t line rules ipt
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${PORT}/udp" >/dev/null 2>&1 || true
    # 80/tcp is shared with TrustTunnel's certbot renewals: keep it if TT uses Let's Encrypt
    if [ "$ST_CERT_MODE" = "letsencrypt" ] && ! grep -qx 'CERT_MODE=letsencrypt' "$TT_STATE" 2>/dev/null; then
      ufw delete allow 80/tcp >/dev/null 2>&1 || true
    fi
  fi
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    for t in filter nat mangle; do
      rules="$("$ipt" -t "$t" -S 2>/dev/null || true)"
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        local -a args
        read -ra args <<<"${line/-A /-D }"
        "$ipt" -t "$t" "${args[@]}" >/dev/null 2>&1 || true
      done < <(grep -E -- "^-A .*--comment \"?(${FW_TAG}|${FW_TAG_ACME}|${FW_TAG_HOP})\"?( |$)" <<<"$rules" || true)
    done
  done
  save_iptables || true
  if command -v nft >/dev/null 2>&1; then
    local fam tbl chain h
    while read -r fam tbl chain h; do
      [ -n "$h" ] && nft delete rule "$fam" "$tbl" "$chain" handle "$h" 2>/dev/null || true
    done < <(nft -a list ruleset 2>/dev/null | awk -v t1="\"$FW_TAG\"" -v t2="\"$FW_TAG_ACME\"" '
      /^table / { fam=$2; tbl=$3 }
      /^[[:space:]]*chain / { chain=$2 }
      /comment/ && (index($0, "comment " t1) || index($0, "comment " t2)) {
        for (i=1;i<=NF;i++) if ($i=="handle") print fam, tbl, chain, $(i+1)
      }')
    nft delete table inet hysteria-hop 2>/dev/null || true
    nft delete table inet hysteria-harden 2>/dev/null || true
    persist_nft
  fi
}

# ---------- network hardening ----------
apply_sysctl() {
  local k v kv changed=0 tmp
  tmp="$(mktmp)/sysctl.conf"; : > "$tmp"
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    [ "$(sysctl -n "$k" 2>/dev/null)" != "$v" ] && changed=1
    printf '%s=%s\n' "$k" "$v" >> "$tmp"
  done
  if [ -f "$SYSCTL_FILE" ] && cmp -s "$tmp" "$SYSCTL_FILE"; then
    log "sysctl: hardening already in place ($SYSCTL_FILE)"
  else
    cp "$tmp" "$SYSCTL_FILE"; log "sysctl: wrote $SYSCTL_FILE"
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
  log "hardening network (same values as the Xray/TrustTunnel scripts)"
  # 16 MB UDP buffers are what quic-go (Hysteria) recommends
  apply_sysctl \
    "net.core.rmem_max=16777216" \
    "net.core.wmem_max=16777216" \
    "net.ipv4.tcp_mtu_probing=1" \
    "net.ipv4.tcp_base_mss=1024" \
    "net.ipv4.tcp_slow_start_after_idle=0" \
    "net.core.default_qdisc=fq" \
    "net.ipv4.tcp_congestion_control=bbr"
  # MSS clamp only matters for TCP; added only if no other script added one
  if mss_clamp_present; then
    log "mss: clamp already present (shared), nothing to add"
  elif command -v iptables >/dev/null 2>&1 && \
       iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
         -m comment --comment "$FW_TAG" -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
    save_iptables || true; log "mss: clamp-to-pmtu enabled (iptables, tagged $FW_TAG)"
  elif command -v nft >/dev/null 2>&1; then
    nft add table inet hysteria-harden 2>/dev/null || true
    nft add chain inet hysteria-harden post '{ type filter hook postrouting priority mangle ; policy accept ; }' 2>/dev/null || true
    nft add rule inet hysteria-harden post tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null \
      && { persist_nft; log "mss: clamp-to-pmtu enabled (nft)"; } || warn "mss: failed to add nft clamp"
  fi
  return 0
}

unharden_network() {
  if [ -f "$SYSCTL_FILE" ]; then
    rm -f "$SYSCTL_FILE"
    log "sysctl: removed $SYSCTL_FILE (runtime values kept; other scripts' files still apply)"
  fi
  return 0   # tagged MSS clamp / nft tables are removed by remove_firewall
}

# ---------- links ----------
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

link_for() {   # link_for USER PASS PORTSPEC LABEL
  local q
  q="sni=$(urlenc "$HY_HOST")"
  if [ "$PINNED" = "1" ]; then q="$q&insecure=1&pinSHA256=${PIN}"; fi
  [ -n "$OBFS_PW" ] && q="$q&obfs=salamander&obfs-password=$(urlenc "$OBFS_PW")"
  printf 'hysteria2://%s:%s@%s:%s/?%s#%s\n' "$(urlenc "$1")" "$(urlenc "$2")" "$PUB_IP" "$3" "$q" "$(urlenc "$4")"
}

write_links() {
  local out="$WORKDIR/links.txt" i
  : > "$out"
  for i in "${!USERS[@]}"; do
    link_for "${USERS[$i]}" "${PASSES[$i]}" "$PORT" "${USERS[$i]}@${PUB_IP}" >> "$out"
  done
  if [ -n "$HOP" ]; then
    printf '# with port hopping (clients that support multi-port, e.g. official/Hiddify/NekoBox):\n' >> "$out"
    for i in "${!USERS[@]}"; do
      link_for "${USERS[$i]}" "${PASSES[$i]}" "${PORT},${HOP}" "${USERS[$i]}-hop@${PUB_IP}" >> "$out"
    done
  fi
  log "links saved to $out"
}

# ---------- client config (official hysteria binary in client mode) ----------
write_client_config() {   # write_client_config OUT SERVER USER PASS SOCKS_LISTEN [HTTP_LISTEN]
  python3 - "$@" "$HY_HOST" "$PINNED" "${PIN:-}" "${OBFS_PW:-}" <<'PY'
import json, sys
a = sys.argv[1:]
out, server, user, pw, socks = a[0:5]
http = a[5] if len(a) == 10 else ""
host, pinned, pin, obfs = a[-4:]
q = json.dumps
L = [f"server: {q(server)}", f"auth: {q(user + ':' + pw)}", "",
     "tls:", f"  sni: {q(host)}"]
if pinned == "1":
    L += ["  insecure: true", f"  pinSHA256: {q(pin)}"]
if obfs:
    L += ["", "obfs:", "  type: salamander", "  salamander:", f"    password: {q(obfs)}"]
L += ["", "quic:", "  initStreamReceiveWindow: 8388608", "  maxStreamReceiveWindow: 8388608",
      "  initConnReceiveWindow: 20971520", "  maxConnReceiveWindow: 20971520",
      "  keepAlivePeriod: 10s", "",
      "transport:", "  udp:", "    hopInterval: 30s", "",
      "socks5:", f"  listen: {q(socks)}"]
if http:
    L += ["", "http:", f"  listen: {q(http)}"]
open(out, "w").write("\n".join(L) + "\n")
PY
}

# ---------- E2E self-test ----------
self_test() {
  log "end-to-end self-test (hysteria client -> 127.0.0.1:${PORT}/udp)"
  local tdir got="" pid
  tdir="$(mktmp)"
  write_client_config "$tdir/c.yaml" "127.0.0.1:${PORT}" "${USERS[0]}" "${PASSES[0]}" "127.0.0.1:10893"
  setsid "$HY_BIN" client --disable-update-check -c "$tdir/c.yaml" </dev/null >"$tdir/c.log" 2>&1 &
  pid=$!
  sleep 3
  for _ in 1 2 3 4; do
    got="$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:10893 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$got" ] && break
    sleep 3
  done
  kill "$pid" 2>/dev/null || true; sleep 1; kill -9 "$pid" 2>/dev/null || true
  if [ "$got" = "$PUB_IP" ]; then
    log "self-test OK (egress IP = $got)"; return 0
  fi
  warn "self-test FAILED (got '${got:-empty}', expected $PUB_IP); client log:"
  tail -n 15 "$tdir/c.log" >&2 || true
  return 1
}

# ---------- diagnostics (--check) ----------
cfg_first_user() {   # prints "user<TAB>pass" of the first user and the obfs password
  python3 - "$CFG" <<'PY' 2>/dev/null || true
import json, re, sys
t = open(sys.argv[1]).read()
m = re.search(r'^obfs:.*?^\s+password:\s*(".*?")\s*$', t, re.S | re.M)
blk = re.search(r'^\s+userpass:\s*\n\s+(".*?")\s*:\s*(".*?")\s*$', t, re.M)
print((json.loads(blk.group(1)) + "\t" + json.loads(blk.group(2))) if blk else "")
print(json.loads(m.group(1)) if m else "")
PY
}

check_setup() {
  set +e
  log "diagnosing Hysteria2 setup (read-only)"
  local issues=0

  if systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then log "  [OK] $UNIT_NAME active"
  else warn "  [!!] $UNIT_NAME is NOT active"; issues=$((issues+1)); fi

  [ -f "$CFG" ] && log "  [OK] config present: $CFG" || { warn "  [!!] no config at $CFG"; issues=$((issues+1)); }

  local o; o="$(port_owners u "$PORT")"
  if grep -q hysteria <<<"$o"; then log "  [OK] listening on udp/${PORT}"
  elif [ -n "$o" ]; then warn "  [!!] udp/${PORT} is taken by: $o"; issues=$((issues+1))
  else warn "  [!!] nothing listens on udp/${PORT}"; issues=$((issues+1)); fi

  # neighbours
  local xp tp; xp="$(xray_ports | tr '\n' ' ')"; tp="$(tt_port)"
  if [ -n "$xp" ]; then
    if systemctl is-active --quiet xray 2>/dev/null; then log "  [OK] Xray active alongside (tcp ${xp% })"
    else warn "  [!!] Xray installed but NOT active -> bash deploy-xray.sh --fix"; issues=$((issues+1)); fi
  fi
  if [ -n "$tp" ]; then
    [ "$tp" = "$PORT" ] && { warn "  [!!] TrustTunnel uses the same port $PORT"; issues=$((issues+1)); }
    if systemctl is-active --quiet trusttunnel 2>/dev/null; then log "  [OK] TrustTunnel active alongside (tcp+udp $tp)"
    else warn "  [!!] TrustTunnel installed but NOT active -> bash deploy-trusttunnel.sh --fix"; issues=$((issues+1)); fi
  fi

  # certificate
  local crt="$CONF_DIR/certs/cert.pem"
  if [ -f "$crt" ]; then
    if openssl x509 -in "$crt" -noout -checkend 1209600 >/dev/null 2>&1; then
      log "  [OK] certificate valid until $(openssl x509 -in "$crt" -noout -enddate | cut -d= -f2)"
    else warn "  [!!] certificate expires within 14 days (or expired)"; issues=$((issues+1)); fi
  fi
  if [ "$ST_CERT_MODE" = "letsencrypt" ]; then
    [ -x "$LE_HOOK" ] && log "  [OK] LE renewal hook present" || { warn "  [!!] LE renewal hook missing"; issues=$((issues+1)); }
  fi

  # firewall + hopping
  local ufw_out ipt_out nft_out ok=0
  ufw_out="$(ufw status 2>/dev/null || true)"
  ipt_out="$(iptables -S INPUT 2>/dev/null || true)"
  nft_out="$(nft list ruleset 2>/dev/null || true)"
  grep -q "^${PORT}/udp" <<<"$ufw_out" && ok=1
  grep -qE -- "-p udp .*--dport ${PORT} .*-j ACCEPT" <<<"$ipt_out" && ok=1
  grep -qE "udp dport ${PORT} .*accept" <<<"$nft_out" && ok=1
  if [ "$ok" = "1" ]; then log "  [OK] firewall allows udp/${PORT}"
  else warn "  [!!] no firewall rule for udp/${PORT}"; issues=$((issues+1)); fi
  if [ -n "$HOP" ]; then
    if hop_present; then log "  [OK] port hopping udp ${HOP} -> ${PORT}"
    else warn "  [!!] port hopping rule for ${HOP} missing"; issues=$((issues+1)); fi
  fi

  # kernel knobs
  local rmax wmax
  rmax="$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)"
  wmax="$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)"
  if [ "${rmax:-0}" -ge 16777216 ] && [ "${wmax:-0}" -ge 16777216 ]; then
    log "  [OK] UDP buffers rmem_max=$rmax wmem_max=$wmax"
  else warn "  [!!] UDP buffers too small (rmem_max=$rmax wmem_max=$wmax): QUIC throughput suffers"; issues=$((issues+1)); fi

  # live tunnel test through the running server
  if [ -x "$HY_BIN" ] && [ -f "$CFG" ] && systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
    local fu u p
    fu="$(cfg_first_user)"
    u="$(printf '%s\n' "$fu" | sed -n '1p' | cut -f1)"
    p="$(printf '%s\n' "$fu" | sed -n '1p' | cut -f2)"
    OBFS_PW="$(printf '%s\n' "$fu" | sed -n '2p')"
    HY_HOST="${ST_HOST:-$HY_HOST}"
    PINNED="0"; PIN=""
    if [ -f "$crt" ] && is_self_signed "$crt"; then PINNED="1"; PIN="$(cert_pin "$crt")"; fi
    PUB_IP="${PUB_IP:-$(detect_ip || true)}"
    USERS=("$u"); PASSES=("$p")
    if [ -n "$u" ] && [ -n "$PUB_IP" ] && self_test >/dev/null 2>&1; then
      log "  [OK] live tunnel test passed (egress $PUB_IP)"
    else
      warn "  [!!] live tunnel test FAILED (run without --check to see the client log)"; issues=$((issues+1))
    fi
  fi

  if systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
    local since errs
    since="$(systemctl show -p ActiveEnterTimestamp --value "$UNIT_NAME" 2>/dev/null)"
    errs="$(journalctl -u "$UNIT_NAME" --since "$since" --no-pager 2>/dev/null | grep -ciE '\bERROR\b|FATAL' || true)"
    [ "${errs:-0}" -gt 0 ] && log "  [--] ${errs} error line(s) since last start: journalctl -u $UNIT_NAME -n 50"
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
  check_setup && { log "nothing to fix"; return 0; }
  log "applying repairs"

  if [ -x "$HY_BIN" ] && [ -f "$UNIT_FILE" ] && ! systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
    warn "  -> $UNIT_NAME not active; restarting"
    fix_perms
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart "$UNIT_NAME" >/dev/null 2>&1 || true
    sleep 3
    systemctl is-active --quiet "$UNIT_NAME" && log "  [fixed] $UNIT_NAME restarted" \
      || warn "  [!!] still down: journalctl -u $UNIT_NAME -n 50"
  fi

  if [ "$ST_CERT_MODE" = "letsencrypt" ] && [ -n "$ST_DOMAIN" ] && \
     ! openssl x509 -in "$CONF_DIR/certs/cert.pem" -noout -checkend 1209600 >/dev/null 2>&1; then
    warn "  -> renewing Let's Encrypt certificate for $ST_DOMAIN"
    DOMAIN="$ST_DOMAIN"; write_le_hook
    fw_allow tcp 80 "$FW_TAG_ACME"
    certbot renew --cert-name "$ST_DOMAIN" --force-renewal --non-interactive >/dev/null 2>&1 \
      && log "  [fixed] certificate renewed" || warn "  [!!] certbot renew failed"
  fi

  HARDEN="1"; harden_network
  open_firewall
  apply_hop

  echo
  log "re-checking after repairs"
  check_setup
  local rc2=$?
  [ "$rc2" -eq 0 ] && log "fix: all problems resolved" || warn "fix: some issues remain, see above"
  return "$rc2"
}

# ---------- uninstall ----------
uninstall() {
  [ -n "$ST_WORKDIR" ] && WORKDIR="$ST_WORKDIR"
  log "uninstalling Hysteria2 (udp $PORT${HOP:+, hop $HOP}) — Xray and TrustTunnel are left untouched"
  systemctl is-active --quiet xray 2>/dev/null && XRAY_WAS_ACTIVE="1"
  systemctl is-active --quiet trusttunnel 2>/dev/null && TT_WAS_ACTIVE="1"

  systemctl stop "$UNIT_NAME" >/dev/null 2>&1 || true
  systemctl disable "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true

  remove_firewall
  unharden_network
  if [ -f "$LE_HOOK" ]; then
    rm -f "$LE_HOOK"
    log "removed LE deploy hook; the certificate stays (certbot delete --cert-name ${ST_DOMAIN:-<domain>})"
  fi
  rm -f "$HY_BIN"
  rm -rf "$CONF_DIR" "$WORKDIR" /var/lib/hysteria
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" >/dev/null 2>&1 || true
  cleanup_tmp

  log "done. verifying leftovers:"
  local left="" p
  for p in "$HY_BIN" "$CONF_DIR" "$UNIT_FILE" "$WORKDIR" "$SYSCTL_FILE" "$LE_HOOK"; do
    [ -e "$p" ] && left="$left $p"
  done
  systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null && left="$left (service still active)"
  iptables-save 2>/dev/null | grep -q -- "--comment \"\?hysteria" && left="$left (iptables rules)"
  verify_neighbours || true
  if [ -n "$left" ]; then warn "leftovers remain:$left"; return 1; fi
  log "no leftovers found"
  return 0
}

# ---------- backup / rollback ----------
BACKUP=""
backup_existing() {
  [ -f "$CFG" ] || return 0
  BACKUP="$WORKDIR/backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP"
  cp -a "$CFG" "$BACKUP"/
  [ -d "$CONF_DIR/certs" ] && cp -a "$CONF_DIR/certs" "$BACKUP"/ || true
  log "backed up existing config to $BACKUP"
}
rollback() {
  if [ -n "$BACKUP" ] && [ -d "$BACKUP" ]; then
    cp -a "$BACKUP/config.yaml" "$CFG"
    [ -d "$BACKUP/certs" ] && cp -a "$BACKUP/certs/." "$CONF_DIR/certs/" || true
    fix_perms
    systemctl restart "$UNIT_NAME" >/dev/null 2>&1 || true
    warn "restored previous config from $BACKUP and restarted $UNIT_NAME"
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
if [ -z "$PUB_IP" ]; then PUB_IP="$(detect_ip)" || die "cannot detect public IP; pass --ip"; fi
mkdir -p "$WORKDIR"
umask 077

# hostname: --domain/--hostname > previous install > Xray's mask domain > www.bing.com
if [ -z "$HY_HOST" ]; then HY_HOST="$(xray_sni)"; [ -n "$HY_HOST" ] || HY_HOST="www.bing.com"; fi
if [ -z "$MASQ" ]; then
  if [ "$CERT_MODE" = "self-signed" ]; then MASQ="https://${HY_HOST}/"; else MASQ="https://www.bing.com/"; fi
fi

REUSE="0"
load_existing && [ "$FORCE" != "1" ] && REUSE="1"
log "public IP: $PUB_IP   udp port: $PORT${HOP:+ (hop $HOP)}   sni: $HY_HOST   cert: $CERT_MODE   users: $NCLIENTS"

if [ "$DRY_RUN" = "1" ]; then
  log "DRY RUN: no system changes"
  D="$WORKDIR/dry-run"; mkdir -p "$D/certs"
  build_users
  case "$CERT_MODE" in
    provided) cert_provided "$D/certs" ;;
    letsencrypt) CERT_PATH="$D/certs/cert.pem"; KEY_PATH="$D/certs/key.pem"
                 warn "dry-run: Let's Encrypt not requested, cert paths are placeholders" ;;
    *) cert_selfsigned "$D/certs" ;;
  esac
  PINNED="0"; PIN=""
  if [ -f "$CERT_PATH" ] && is_self_signed "$CERT_PATH"; then PINNED="1"; PIN="$(cert_pin "$CERT_PATH")"; fi
  write_config "$D/config.yaml"
  write_links
  write_client_config "$WORKDIR/client.yaml" "${PUB_IP}:${PORT}${HOP:+,$HOP}" "${USERS[0]}" "${PASSES[0]}" "127.0.0.1:1080" "127.0.0.1:10809"
  echo "--- config: $D/config.yaml ; client: $WORKDIR/client.yaml ---"
  echo "--- links ---"; cat "$WORKDIR/links.txt"
  exit 0
fi

check_coexistence
install_hy
ensure_user
mkdir -p "$CONF_DIR/certs"

if [ "$REUSE" = "1" ]; then
  log "existing config found: reusing ${#EXIST_USERS[@]} user(s), passwords and certificate"
  log "(run with --force to rotate them and issue new links)"
fi
build_users
backup_existing

case "$CERT_MODE" in
  provided)    cert_provided "$CONF_DIR/certs" ;;
  letsencrypt) cert_letsencrypt "$CONF_DIR/certs" ;;
  *)           cert_selfsigned "$CONF_DIR/certs" ;;
esac
PINNED="0"; PIN=""
if is_self_signed "$CERT_PATH"; then PINNED="1"; PIN="$(cert_pin "$CERT_PATH")"; fi

write_config "$CFG"
fix_perms
write_state

write_unit
systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null 2>&1 || true
systemctl restart "$UNIT_NAME"
sleep 3
if ! systemctl is-active --quiet "$UNIT_NAME"; then
  journalctl -u "$UNIT_NAME" -n 15 --no-pager >&2 2>/dev/null || true
  rollback
  die "$UNIT_NAME did not start (config rejected?); see: journalctl -u $UNIT_NAME -n 50"
fi
log "hysteria active on udp/${PORT}"

open_firewall
apply_hop
harden_network
write_links
write_client_config "$WORKDIR/client.yaml" "${PUB_IP}:${PORT}${HOP:+,$HOP}" "${USERS[0]}" "${PASSES[0]}" "127.0.0.1:1080" "127.0.0.1:10809"
log "CLI client config written to $WORKDIR/client.yaml (socks5 :1080, http :10809)"

if [ "$SKIP_TEST" != "1" ] && ! self_test; then
  warn "config is installed but the tunnel self-test failed."
  rollback
  verify_neighbours || true
  warn "Inspect: journalctl -u $UNIT_NAME -n 50"
  exit 2
fi
verify_neighbours || warn "Hysteria2 is up, but check the other services (--check of their scripts)"

echo
log "DONE. Hysteria2 links:"
grep -v '^#' "$WORKDIR/links.txt"
if command -v qrencode >/dev/null 2>&1; then
  echo; log "QR for ${USERS[0]}:"
  qrencode -t ANSIUTF8 "$(head -n1 "$WORKDIR/links.txt")" || true
fi
echo
log "server: ${PUB_IP}:${PORT}/udp${HOP:+  hop: $HOP}   sni: $HY_HOST   cert: $CERT_MODE"
[ "$PINNED" = "1" ] && log "pinSHA256: $PIN"
[ -n "$OBFS_PW" ] && log "obfs: salamander (masquerade disabled)" || log "masquerade: $MASQ (HTTP/3 only; TCP 443 stays Xray's)"
log "config: $CFG   links: $WORKDIR/links.txt   client: $WORKDIR/client.yaml"
[ "$HARDEN" = "1" ] && log "hardening: $SYSCTL_FILE"
[ -n "$XRAY_PORTS" ] && log "Xray untouched (tcp ${XRAY_PORTS% })"
[ -n "$TT_PORT" ] && log "TrustTunnel untouched (tcp+udp $TT_PORT)"
exit 0
