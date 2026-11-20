#!/usr/bin/env bash
#
# deploy-xray.sh — one-command Xray VLESS+REALITY deploy (no web panel).
#
# Installs Xray, generates REALITY keys + UUIDs, writes a hardened config,
# a systemd unit and firewall rules, runs an end-to-end self-test and prints
# ready-to-use vless:// links (also saved to <workdir>/links.txt).
#
# Usage:
#   bash deploy-xray.sh [options]
#
# Options:
#   --sni DOMAIN      REALITY mask domain (default: www.bing.com)
#   --ip IP           public IP to advertise in links (default: autodetect)
#   --port PORT       listen port (default: 443)
#   --clients N       number of client UUIDs to create (default: 3)
#   --name PREFIX     label prefix for links (default: reality)
#   --bin PATH        use a local xray binary instead of downloading
#   --workdir DIR     where to store links.txt + config backup (default: /root/xray-deploy)
#   --force           regenerate keys/UUIDs even if a config already exists (reset)
#   --uninstall       remove Xray, config, logs, unit, firewall rule and workdir
#   --check           diagnose the running setup and report (no changes)
#   --fix             diagnose, then auto-repair what is safely fixable
#                     (restart the service, re-apply network hardening, re-open
#                     the firewall port) and re-check; never rewrites the config
#                     or rotates keys, so existing client links keep working
#   --no-harden       skip network hardening (keepalive / MTU probing / MSS clamp)
#   --with-mux        also emit a mux client profile (NOTE: mux is incompatible
#                     with xtls-rprx-vision, so that profile drops the flow and
#                     is offered only as a fallback; vision stays the default)
#   --dry-run         generate config + links, do not touch the system
#   -h, --help        show this help
#
# Notes:
#   * The first link is also printed as a QR code in the terminal (qrencode is
#     installed automatically if missing; skipped silently if it can't be).
#   * Idempotent by default: re-running on an already-configured server REUSES the
#     existing REALITY key, shortId and client UUIDs, so the service is refreshed
#     without invalidating client links. Use --force to explicitly rotate everything.
#   * Tested on Debian 11/12 and Ubuntu 20.04/22.04/24.04 (systemd).
#   * Anti-drop hardening (on by default, disable with --no-harden):
#       - TCP keepalive in the xray config (sockopt), so dead flows are detected in
#         ~30s instead of waiting for the 2-hour OS default;
#       - net.ipv4.tcp_mtu_probing=1 + BBR/fq, persisted in /etc/sysctl.d;
#       - MSS clamping (iptables mangle / nft) for PMTU-blackhole paths.
#     A client config with keepalive (vision) is written to <workdir>/client.json;
#     --with-mux adds a flow-less mux fallback profile.
#   * Firewall: opens the listen port via ufw, else iptables, else nftables
#     (nft-only hosts get a rule in the first input-hook chain, else a new
#     'table inet filter' / 'chain input'); the ruleset is saved to
#     /etc/nftables.conf and nftables.service is enabled so it survives reboot.
#   * Realistic SNI is critical: the mask domain must support TLS1.3 + h2 + X25519
#     and be reachable from the server. The script verifies this before applying.
#   * Some domains break REALITY relaying (e.g. www.microsoft.com behind Akamai).
#     The script E2E-tests the tunnel and refuses to finish on failure.
#
set -euo pipefail

# ---------- defaults ----------
SNI="www.bing.com"
PUB_IP=""
PORT="443"
NCLIENTS="3"
NAME="reality"
XBIN=""
WORKDIR="/root/xray-deploy"
DRY_RUN="0"
FORCE="0"
UNINSTALL="0"
CHECK="0"
FIX="0"
HARDEN="1"
WITH_MUX="0"
MUX_UUID=""
EXIST_PRIV=""
EXIST_SHORTID=""
EXIST_MUX_UUID=""
XRAY_VERSION="${XRAY_VERSION:-26.4.25}"

# ---------- helpers ----------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# temp dirs created during a run; removed on any exit so nothing is left behind
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
    --sni)      SNI="$2"; shift 2 ;;
    --ip)       PUB_IP="$2"; shift 2 ;;
    --port)     PORT="$2"; shift 2 ;;
    --clients)  NCLIENTS="$2"; shift 2 ;;
    --name)     NAME="$2"; shift 2 ;;
    --bin)      XBIN="$2"; shift 2 ;;
    --workdir)  WORKDIR="$2"; shift 2 ;;
    --force)    FORCE="1"; shift ;;
    --uninstall) UNINSTALL="1"; shift ;;
    --check)    CHECK="1"; shift ;;
    --fix)      FIX="1"; shift ;;
    --no-harden) HARDEN="0"; shift ;;
    --with-mux) WITH_MUX="1"; shift ;;
    --dry-run)  DRY_RUN="1"; shift ;;
    -h|--help)  usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
case "$NCLIENTS" in ''|*[!0-9]*) die "--clients must be a number" ;; esac
[ "$NCLIENTS" -ge 1 ] || die "--clients must be >= 1"

# ---------- prerequisites ----------
ensure_prereqs() {
  local need=""
  command -v curl >/dev/null 2>&1 || need="$need curl"
  command -v unzip >/dev/null 2>&1 || need="$need unzip"
  command -v python3 >/dev/null 2>&1 || need="$need python3"
  if [ -n "$need" ]; then
    log "installing prerequisites:$need"
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq $need ca-certificates
  fi
  # optional: terminal QR codes for the links
  command -v qrencode >/dev/null 2>&1 || apt-get install -y -qq qrencode >/dev/null 2>&1 || true
}

# ---------- detect public IP ----------
detect_ip() {
  local ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip="$(curl -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]')" || true
    case "$ip" in
      *[!0-9a-fA-F:.]*|"") continue ;;
      *.*|*:*) echo "$ip"; return 0 ;;
    esac
  done
  return 1
}

if [ "$UNINSTALL" != "1" ] && [ "$CHECK" != "1" ] && [ "$FIX" != "1" ]; then
  if [ "$DRY_RUN" != "1" ]; then
    ensure_prereqs
  fi
  if [ -z "$PUB_IP" ]; then
    PUB_IP="$(detect_ip)" || die "cannot detect public IP; pass --ip"
  fi
  log "public IP: $PUB_IP   sni: $SNI   port: $PORT   clients: $NCLIENTS"

  mkdir -p "$WORKDIR"
  umask 077
fi

# ---------- install / locate xray ----------
install_xray() {
  if [ -n "$XBIN" ]; then
    [ -x "$XBIN" ] || die "--bin $XBIN is not executable"
    install -m 0755 "$XBIN" /usr/local/bin/xray
    # try to fetch geo data next to a sibling install, else download
    local geodir; geodir="$(dirname "$XBIN")"
    mkdir -p /usr/local/share/xray
    for f in geoip.dat geosite.dat; do
      if [ -f "$geodir/$f" ]; then install -m 0644 "$geodir/$f" "/usr/local/share/xray/$f"; fi
    done
  fi
  if [ ! -x /usr/local/bin/xray ]; then
    log "downloading Xray v${XRAY_VERSION}"
    apt-get update -qq
    apt-get install -y -qq curl unzip ca-certificates
    local tmp; tmp="$(mktmp)"
    curl -fsSL -o "$tmp/x.zip" \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
    unzip -q -o "$tmp/x.zip" -d "$tmp/x"
    install -m 0755 "$tmp/x/xray" /usr/local/bin/xray
    rm -rf "$tmp"
  fi
  mkdir -p /usr/local/share/xray
  chmod 755 /usr/local/share/xray
  # ensure geo data present (needed by routing geoip:private)
  if [ ! -f /usr/local/share/xray/geoip.dat ]; then
    log "fetching geoip/geosite data"
    local tmp2; tmp2="$(mktmp)"
    curl -fsSL -o "$tmp2/x.zip" \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
    unzip -q -o "$tmp2/x.zip" -d "$tmp2/x"
    install -m 0644 "$tmp2/x/geoip.dat"   /usr/local/share/xray/geoip.dat
    install -m 0644 "$tmp2/x/geosite.dat" /usr/local/share/xray/geosite.dat
    rm -rf "$tmp2"
  fi
  /usr/local/bin/xray version
}

# ---------- verify the mask domain is a usable REALITY dest ----------
verify_sni() {
  log "checking mask domain $SNI (reachability + TLS1.3 + h2 + cert)"
  python3 - "$SNI" <<'PY'
import socket, ssl, sys
host=sys.argv[1]
try:
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2","http/1.1"])
    with socket.create_connection((host,443),timeout=10) as s:
        with ctx.wrap_socket(s,server_hostname=host) as ss:
            if ss.version()!="TLSv1.3":
                print(f"  WARN: {host} negotiated {ss.version()}, REALITY prefers TLS1.3")
            if ss.selected_alpn_protocol()!="h2":
                print(f"  WARN: {host} ALPN={ss.selected_alpn_protocol()}, h2 preferred")
            print(f"  OK: {host} reachable, {ss.version()}, ALPN={ss.selected_alpn_protocol()}")
except Exception as e:
    print(f"  FAIL: {host}: {type(e).__name__}: {e}")
    sys.exit(1)
PY
}

# ---------- generate keys ----------
gen_keys() {
  local out priv pub
  out="$(/usr/local/bin/xray x25519)"
  priv="$(printf '%s\n' "$out" | awk -F': *' '/Private/{print $2}')"
  pub="$(printf '%s\n' "$out" | awk -F': *' '/Public|Password/{print $2}')"
  [ -n "$priv" ] && [ -n "$pub" ] || die "failed to generate x25519 keypair"
  PRIV="$priv"; PUB="$pub"
  SHORTID="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

gen_uuid_one() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
  else
    python3 -c 'import uuid;print(uuid.uuid4())'
  fi
}

gen_uuids() {
  UUIDS=()
  local i
  for i in $(seq 1 "$NCLIENTS"); do
    UUIDS+=("$(gen_uuid_one)")
  done
}

# ---------- reuse an existing install (idempotent re-run) ----------
# Reads privateKey / shortId / client UUIDs out of an existing config so that a
# re-run refreshes the service WITHOUT rotating credentials (client links stay valid).
load_existing() {
  local cfg="$1"
  [ -f "$cfg" ] || return 1
  local out
  out="$(python3 - "$cfg" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    ib = d["inbounds"][0]
    rs = ib["streamSettings"]["realitySettings"]
    clients = ib["settings"]["clients"]
    print(rs.get("privateKey",""))
    print((rs.get("shortIds") or [""])[0])
    # vision users (have flow) then mux users (no flow), separated by a marker
    for c in clients:
        if c.get("flow"):
            print(c["id"])
    print("--MUX--")
    for c in clients:
        if not c.get("flow"):
            print(c["id"])
except Exception:
    sys.exit(1)
PY
)" || return 1
  EXIST_PRIV="$(printf '%s\n' "$out" | sed -n '1p')"
  EXIST_SHORTID="$(printf '%s\n' "$out" | sed -n '2p')"
  local flow_ids mux_ids
  flow_ids="$(printf '%s\n' "$out" | sed -n '3,$p' | sed '/^--MUX--$/,$d')"
  mux_ids="$(printf '%s\n' "$out" | sed -n '/^--MUX--$/,$p' | sed '1d')"
  EXIST_UUIDS=( $flow_ids )
  EXIST_MUX_UUID="$(printf '%s\n' "$mux_ids" | sed -n '1p')"
  [ -n "$EXIST_PRIV" ] || return 1
  return 0
}

# derive the public key from a private key (REALITY x25519)
derive_pub() {
  /usr/local/bin/xray x25519 -i "$1" 2>/dev/null \
    | awk -F': *' '/Public|Password/{print $2; exit}'
}

# ---------- write config ----------
write_config() {
  local cfg="$1"
  python3 - "$cfg" "$PORT" "$SNI" "$PRIV" "$SHORTID" "$NAME" "${UUIDS[@]}" "$MUX_UUID" <<'PY'
import json, sys
cfg, port, sni, priv, sid, name = sys.argv[1:7]
mux_uuid = sys.argv[-1]
uuids = sys.argv[7:-1]
clients=[{"email": f"{name}-{i+1}" if i else f"{name}-{port}",
          "flow":"xtls-rprx-vision","id":u} for i,u in enumerate(uuids)]
# mux is incompatible with xtls-rprx-vision, so the mux fallback profile needs a
# separate user WITHOUT flow.
if mux_uuid:
    clients.append({"email": f"{name}-mux","id":mux_uuid})
conf={
  "log":{"access":"none","error":"/var/log/xray/error.log","loglevel":"warning"},
  "routing":{"domainStrategy":"AsIs","rules":[
    {"type":"field","outboundTag":"blocked","ip":["geoip:private"]},
    {"type":"field","outboundTag":"blocked","protocol":["bittorrent"]}]},
  "inbounds":[{
    "listen":"0.0.0.0","port":int(port),"protocol":"vless",
    "settings":{"clients":clients,"decryption":"none","fallbacks":[]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
      "show":False,"dest":f"{sni}:443","xver":0,"serverNames":[sni],
      "privateKey":priv,"shortIds":[sid]},
      "tcpSettings":{"acceptProxyProtocol":False,"header":{"type":"none"}},
      "sockopt":{"tcpKeepAliveIdle":30,"tcpKeepAliveInterval":15}},
    "tag":f"inbound-{port}",
    "sniffing":{"enabled":False,"destOverride":["http","tls","quic","fakedns"],
                "metadataOnly":False,"routeOnly":False}}],
  "outbounds":[
    {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}},
    {"tag":"blocked","protocol":"blackhole","settings":{}}]}
json.dump(conf, open(cfg,"w"), indent=2)
print(f"  wrote {cfg}")
PY
}

# ---------- write systemd unit ----------
write_unit() {
  cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=nobody
Environment="XRAY_LOCATION_ASSET=/usr/local/share/xray"
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

# ---------- firewall ----------
# Find an existing nft chain with an input hook; print "family table chain".
# Reads all input (no early exit) so nft is never killed by SIGPIPE under pipefail.
nft_input_target() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list chains 2>/dev/null | awk '
    /^table / { fam=$2; tbl=$3 }
    /^[[:space:]]*chain / { chain=$2 }
    /hook input/ { if (!done) { print fam, tbl, chain; done=1 } }
  '
}

# Persist the current nftables ruleset across reboots (standard dump location).
persist_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list ruleset > /etc/nftables.conf 2>/dev/null || return 0
  command -v systemctl >/dev/null 2>&1 && systemctl enable nftables >/dev/null 2>&1 || true
  log "nft: ruleset saved to /etc/nftables.conf (nftables.service enabled)"
}

open_firewall_nft() {
  local tgt fam tbl chain
  tgt="$(nft_input_target)"
  fam=""; tbl=""; chain=""
  if [ -n "$tgt" ]; then read -r fam tbl chain <<<"$tgt" || true; fi
  if [ -z "$fam" ]; then
    log "nft: no input chain found; creating 'table inet filter' / 'chain input'"
    nft add table inet filter 2>/dev/null || true
    nft add chain inet filter input '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true
    fam=inet; tbl=filter; chain=input
  fi
  local rules
  rules="$(nft list chain "$fam" "$tbl" "$chain" 2>/dev/null || true)"
  if grep -Eq "tcp dport( \{)? $PORT(,|\}| |$)" <<<"$rules"; then
    log "nft: rule for tcp/${PORT} already present in $fam/$tbl/$chain"
  elif nft add rule "$fam" "$tbl" "$chain" tcp dport "$PORT" accept 2>/dev/null; then
    log "nft: allowed tcp/${PORT} in $fam/$tbl/$chain"
  else
    warn "nft: failed to add rule for tcp/${PORT}"
  fi
  persist_nft
}

remove_firewall_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  local tgt fam tbl chain h
  tgt="$(nft_input_target)"
  [ -n "$tgt" ] || return 0
  fam=""; tbl=""; chain=""
  read -r fam tbl chain <<<"$tgt" || true
  [ -n "$fam" ] || return 0
  for h in $(nft -a list chain "$fam" "$tbl" "$chain" 2>/dev/null | awk -v p="$PORT" '
      /tcp dport/ && $0 ~ ("dport( \\{)? " p "(,|\\}| |$)") && /accept/ {
        for (i=1;i<=NF;i++) if ($i=="handle") print $(i+1)
      }'); do
    nft delete rule "$fam" "$tbl" "$chain" handle "$h" 2>/dev/null || true
  done
}

open_firewall() {
  local fw_done=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
    ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
    log "ufw: allowed ${PORT}/tcp"
    fw_done=1
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || \
      iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
      log "iptables: allowed tcp/${PORT} (saved)"
    else
      log "iptables: allowed tcp/${PORT} (not persisted; install iptables-persistent)"
    fi
    fw_done=1
  fi
  # nftables-only systems (no ufw, no iptables)
  if [ "$fw_done" = "0" ] && command -v nft >/dev/null 2>&1; then
    open_firewall_nft
  fi
}

# ---------- network hardening (anti-drop) ----------
# DPI/NAT on the client<->server path silently blackholes idle or fragmented flows.
# These settings make xray/kernel detect and recover from that far sooner.
SYSCTL_FILE="/etc/sysctl.d/99-xray-hardening.conf"

# write sysctl values and apply them now; idempotent
apply_sysctl() {
  local k v changed=0
  local tmp; tmp="$(mktmp)/sysctl.conf"
  : > "$tmp"
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    if [ "$(sysctl -n "$k" 2>/dev/null)" != "$v" ]; then changed=1; fi
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
  [ "$changed" = "1" ] && log "sysctl: applied hardening (mtu_probing, bbr, buffers)"
  return 0
}

# MSS clamp on the SYN path so hosts behind PPPoE/PMTU-blackhole links can connect.
# Prefers iptables mangle, falls back to nft.
harden_mss_iptables() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || \
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || return 1
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
  log "mss: clamp-to-pmtu enabled (iptables mangle)"
  return 0
}

harden_mss_nft() {
  command -v nft >/dev/null 2>&1 || return 1
  local rules; rules="$(nft list ruleset 2>/dev/null || true)"
  grep -qE "clamp-mss-to-pmtu|maxseg size set" <<<"$rules" && { log "mss: clamp already present (nft)"; return 0; }
  nft add table inet xray-harden 2>/dev/null || true
  nft add chain inet xray-harden post '{ type filter hook postrouting priority mangle ; policy accept ; }' 2>/dev/null || true
  nft add rule inet xray-harden post tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null || return 1
  persist_nft
  log "mss: clamp-to-pmtu enabled (nft)"
  return 0
}

harden_network() {
  [ "$HARDEN" = "1" ] || { log "hardening skipped (--no-harden)"; return 0; }
  log "hardening network against silent drops"
  apply_sysctl \
    "net.ipv4.tcp_mtu_probing=1" \
    "net.ipv4.tcp_base_mss=1024" \
    "net.ipv4.tcp_slow_start_after_idle=0" \
    "net.core.default_qdisc=fq" \
    "net.ipv4.tcp_congestion_control=bbr" \
    "net.core.rmem_max=16777216" \
    "net.core.wmem_max=16777216"
  harden_mss_iptables || harden_mss_nft || warn "mss: no iptables/nft backend; skipped clamp"
  # record a baseline so --check can measure the abort rate SINCE hardening
  if command -v nstat >/dev/null 2>&1; then
    local b; b="$(nstat -az 2>/dev/null | awk '/TcpExtTCPAbortOnTimeout/{print $2}')"
    case "$b" in ''|*[!0-9]*) b="" ;; esac
    [ -n "$b" ] && printf '%s %s\n' "$(date +%s)" "$b" > "$WORKDIR/.tcpbaseline" 2>/dev/null || true
  fi
  return 0
}

# remove hardening (sysctl file + MSS clamp) — called by uninstall
unharden_network() {
  if [ -f "$SYSCTL_FILE" ]; then
    rm -f "$SYSCTL_FILE"
    log "sysctl: removed $SYSCTL_FILE"
  fi
  if command -v iptables >/dev/null 2>&1; then
    while iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; do
      iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || break
    done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet xray-harden 2>/dev/null || true
    persist_nft
  fi
  return 0
}

# ---------- uninstall ----------
uninstall() {
  log "uninstalling Xray (port $PORT, workdir $WORKDIR)"

  # 1. stop and disable the service
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop xray >/dev/null 2>&1 || true
    systemctl disable xray >/dev/null 2>&1 || true
  fi

  # 2. remove the systemd unit
  rm -f /etc/systemd/system/xray.service
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
  command -v systemctl >/dev/null 2>&1 && systemctl reset-failed xray >/dev/null 2>&1 || true

  # 3. firewall rule for this port (removal is idempotent; try every backend present)
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1; do
      iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || break
    done
    command -v netfilter-persistent >/dev/null 2>&1 && \
      netfilter-persistent save >/dev/null 2>&1 || true
  fi
  if command -v nft >/dev/null 2>&1; then
    remove_firewall_nft
    persist_nft
  fi

  # 4. network hardening (sysctl file + MSS clamp)
  unharden_network

  # 5. files: binary, geo data, config, logs
  rm -f /usr/local/bin/xray
  rm -rf /usr/local/share/xray
  rm -rf /usr/local/etc/xray
  rm -rf /var/log/xray

  # 5. workdir (links + config backups) and any leftover temp dirs
  rm -rf "$WORKDIR"
  cleanup_tmp

  # 6. report what remains
  log "done. verifying leftovers:"
  local left=""
  for p in /usr/local/bin/xray /usr/local/share/xray /usr/local/etc/xray \
           /var/log/xray /etc/systemd/system/xray.service "$WORKDIR" "$SYSCTL_FILE"; do
    if [ -e "$p" ]; then left="$left $p"; fi
  done
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray 2>/dev/null; then
    left="$left (service still active)"
  fi
  if [ -n "$left" ]; then
    warn "leftovers remain:$left"
    return 1
  fi
  log "no leftovers found"
  return 0
}


# ---------- client config ----------
# Default profile: xtls-rprx-vision + TCP keepalive (vision is the anti-DPI core).
# With --with-mux an EXTRA profile is emitted that uses mux.cool on a flow-less
# user: mux collapses many TCP flows into one (good against churn) but is
# INCOMPATIBLE with vision, so it is a fallback, not the default.
write_client_config() {
  local out="$WORKDIR/client.json"
  python3 - "$out" "$PUB_IP" "$PORT" "$SNI" "$PUB" "$SHORTID" "${UUIDS[0]}" "$MUX_UUID" "$WITH_MUX" <<'PY'
import json, sys
out, ip, port, sni, pbk, sid, uuid, mux_uuid, with_mux = sys.argv[1:10]
port = int(port)

def stream():
    return {"network":"tcp","security":"reality",
            "realitySettings":{"serverName":sni,"fingerprint":"chrome",
                               "publicKey":pbk,"shortId":sid,"spiderX":"/"},
            "sockopt":{"tcpKeepAliveIdle":30,"tcpKeepAliveInterval":15}}

def outbound(u, flow, mux=None):
    user = {"id":u,"encryption":"none"}
    if flow: user["flow"] = flow
    ob = {"protocol":"vless",
          "settings":{"vnext":[{"address":ip,"port":port,"users":[user]}]},
          "streamSettings":stream()}
    if mux is not None: ob["mux"] = mux
    return ob

outbounds = [outbound(uuid, "xtls-rprx-vision")]
tags = ["proxy-vision"]
if with_mux == "1" and mux_uuid:
    outbounds.append(outbound(mux_uuid, None, {"enabled":True,"concurrency":8,
                                               "xudpConcurrency":16,"xudpProxyUDP443":"reject"}))
    tags.append("proxy-mux")
for ob, t in zip(outbounds, tags):
    ob["tag"] = t
conf = {"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":True}},
                    {"listen":"127.0.0.1","port":10809,"protocol":"http","settings":{"udp":True}}],
        "outbounds":outbounds}
if len(outbounds) > 1:
    conf["routing"] = {"domainStrategy":"AsIs",
                       "rules":[{"type":"field","inboundTag":["socks","http"],
                                 "outboundTag":"proxy-vision"}]}
json.dump(conf, open(out,"w"), indent=2)
print(f"  wrote {out} (profiles: {', '.join(tags)})")
PY
}

# ---------- diagnostics (--check) ----------
check_setup() {
  # diagnostics must never abort the script (probes may be missing in containers)
  set +e
  log "diagnosing Xray setup (read-only)"
  local issues=0

  # service
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray 2>/dev/null; then
    log "  [OK] xray service active"
  else
    warn "  [!!] xray service is NOT active"; issues=$((issues+1))
  fi

  # config present + valid
  local cfg="/usr/local/etc/xray/config.json"
  if [ -f "$cfg" ]; then
    log "  [OK] config present: $cfg"
    if [ -x /usr/local/bin/xray ] && /usr/local/bin/xray run -test -config "$cfg" >/dev/null 2>&1; then
      log "  [OK] config passes xray -test"
    else
      warn "  [!!] config FAILS xray -test"; issues=$((issues+1))
    fi
    # keepalive present?
    if grep -q '"sockopt"' "$cfg" 2>/dev/null; then
      log "  [OK] sockopt (TCP keepalive) present in config"
    else
      warn "  [!!] no sockopt in config -> dead flows not detected for up to 2h"
      warn "       fix: re-run without --no-harden (adds tcpKeepAliveIdle=30)"
      issues=$((issues+1))
    fi
  else
    warn "  [!!] no config at $cfg"; issues=$((issues+1))
  fi

  # kernel keepalive (informational; sockopt overrides it per-socket)
  local ka; ka="$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')"
  log "  [--] net.ipv4.tcp_keepalive_time=$ka (sockopt in config takes precedence)"

  # mtu probing
  local mp; mp="$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo '?')"
  if [ "$mp" = "1" ]; then log "  [OK] tcp_mtu_probing=1"; else
    warn "  [!!] tcp_mtu_probing=$mp (PMTU blackholes may stall big transfers)"; issues=$((issues+1)); fi

  # MSS clamp
  # NOTE: capture output first — piping nft/iptables into `grep -q` triggers
  # SIGPIPE on the producer and, with `set -o pipefail`, fails the whole test.
  local mangle_rules nft_rules
  mangle_rules="$(iptables -t mangle -S 2>/dev/null || true)"
  nft_rules="$(nft list ruleset 2>/dev/null || true)"
  if grep -q "clamp-mss-to-pmtu" <<<"$mangle_rules"; then
    log "  [OK] MSS clamp present (iptables mangle)"
  elif grep -qE "clamp-mss-to-pmtu|maxseg size set" <<<"$nft_rules"; then
    log "  [OK] MSS clamp present (nft)"
  else
    warn "  [!!] no MSS clamp (PPPoE/PMTU-blackhole clients may fail)"; issues=$((issues+1))
  fi

  # firewall open
  local fw_open=0 ufw_out ipt_out
  ufw_out="$(ufw status 2>/dev/null || true)"
  ipt_out="$(iptables -S INPUT 2>/dev/null || true)"
  grep -q "^${PORT}/tcp" <<<"$ufw_out" && fw_open=1
  grep -q -- "--dport ${PORT} -j ACCEPT" <<<"$ipt_out" && fw_open=1
  grep -qE "dport( \{)? ${PORT}(,|\}| |$)" <<<"$nft_rules" && fw_open=1
  if [ "$fw_open" = "1" ]; then log "  [OK] firewall allows tcp/${PORT}"; else
    warn "  [!!] no firewall rule for tcp/${PORT}"; issues=$((issues+1)); fi

  # recent REALITY handshake failures (DPI fingerprint), since the last xray start
  if [ -f /var/log/xray/error.log ]; then
    local bad; bad="$(awk '/started$/{buf=""} {buf=buf"\n"$0} END{print buf}' /var/log/xray/error.log 2>/dev/null | grep -c "failed to read client hello" || true)"
    if [ "${bad:-0}" -gt 0 ]; then
      warn "  [!!] ${bad} 'failed to read client hello' since last start -> likely DPI/MTU mangling"
      warn "       try: vision+keepalive client.json, hysteria2 fallback, or another --sni"
      issues=$((issues+1))
    else
      log "  [OK] no REALITY client-hello failures since last start"
    fi
  fi

  # TCP abort/timeout pressure (a proxy for silent drops on the client path).
  # Absolute counters are cumulative since boot, so a lifetime average is
  # meaningless after hardening — measure the rate SINCE hardening (baseline
  # written by harden_network) or, failing that, over a short live sample.
  local ab="" rt="" base_file="$WORKDIR/.tcpbaseline" rate="" note=""
  if command -v nstat >/dev/null 2>&1; then
    ab="$(nstat -az 2>/dev/null | awk '/TcpExtTCPAbortOnTimeout/{print $2}')"
    rt="$(nstat -az 2>/dev/null | awk '/TcpExtTCPLostRetransmit/{print $2}')"
  fi
  case "$ab" in ''|*[!0-9]*) ab="" ;; esac
  if [ -n "$ab" ] && [ -f "$base_file" ]; then
    local be bc; read -r be bc < "$base_file" 2>/dev/null
    local now; now="$(date +%s)"
    case "$be" in ''|*[!0-9]*) be=0 ;; esac
    case "$bc" in ''|*[!0-9]*) bc=0 ;; esac
    if [ "$now" -gt "$be" ] && [ "$ab" -ge "$bc" ]; then
      rate=$(( (ab - bc) * 60 / (now - be) ))
      note="since hardening ($(( (now - be) / 60 )) min ago)"
    fi
  fi
  if [ -z "$rate" ] && [ -n "$ab" ]; then
    # no baseline: fall back to a short live sample
    sleep 10
    local ab2; ab2="$(nstat -az 2>/dev/null | awk '/TcpExtTCPAbortOnTimeout/{print $2}')"
    case "$ab2" in ''|*[!0-9]*) ab2="$ab" ;; esac
    rate=$(( (ab2 - ab) * 6 ))
    note="10s live sample"
  fi
  if [ -n "$rate" ]; then
    if [ "$rate" -gt 5 ]; then
      warn "  [!!] TCPAbortOnTimeout ~${rate}/min ${note} -> path is still dropping flows"
      warn "       if this persists, try another --sni or the hysteria2 fallback"
      issues=$((issues+1))
    else
      log "  [OK] TCPAbortOnTimeout ~${rate}/min ${note} (total ${ab}), TCPLostRetransmit=${rt:-?}"
    fi
  else
    log "  [--] TCP counters unavailable (nstat missing)"
  fi

  echo
  if [ "$issues" -eq 0 ]; then
    log "check: no problems found"
    return 0
  fi
  warn "check: $issues issue(s) found (see above)"
  return 1
}

# ---------- auto-repair (--fix) ----------
# Runs the diagnostics, then applies the safe, idempotent repairs for whatever
# it found, and re-checks. Only touches things the installer itself manages:
# service state, network hardening and the firewall rule. It never rewrites an
# existing config (so client links stay valid) and never rotates keys.
fix_setup() {
  set +e
  mkdir -p "$WORKDIR" 2>/dev/null || true
  log "auto-repair (--fix): diagnosing first"
  check_setup
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    log "nothing to fix"
    return 0
  fi

  log "applying repairs"

  # 1) service not running -> try to bring it up
  if ! systemctl is-active --quiet xray 2>/dev/null; then
    warn "  -> xray not active; restarting"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart xray >/dev/null 2>&1 || true
    sleep 3
    systemctl is-active --quiet xray 2>/dev/null && log "  [fixed] xray restarted" \
      || warn "  [!!] xray still down: journalctl -u xray -n 50"
  fi

  # 2) network hardening (sysctl + MSS clamp) — idempotent, also adds the
  #    sockopt-adjacent kernel knobs. Re-run unconditionally; it is a no-op
  #    when everything is already correct.
  HARDEN="1"
  harden_network

  # 3) firewall rule for the listen port
  open_firewall

  echo
  log "re-checking after repairs"
  check_setup
  local rc2=$?
  if [ "$rc2" -eq 0 ]; then
    log "fix: all problems resolved"
  else
    warn "fix: some issues remain (likely config-level: SNI/DPI). See --check output."
  fi
  return "$rc2"
}

# ---------- links ----------
write_links() {
  local out="$WORKDIR/links.txt"
  : > "$out"
  local i=0
  for u in "${UUIDS[@]}"; do
    i=$((i+1))
    local label="${NAME}-${i}"
    [ "$i" -eq 1 ] && label="${NAME}-${PORT}"
    local link="vless://${u}@${PUB_IP}:${PORT}?type=tcp&security=reality&pbk=${PUB}&fp=chrome&sni=${SNI}&sid=${SHORTID}&spx=%2F&flow=xtls-rprx-vision#${label}"
    printf '%s\n' "$link" >> "$out"
  done
  log "links saved to $out"
}

# ---------- E2E self-test ----------
self_test() {
  log "end-to-end self-test"
  local tdir; tdir="$(mktmp)"
  cat > "$tdir/c.json" <<EOF
{
  "log":{"loglevel":"warning"},
  "inbounds":[{"listen":"127.0.0.1","port":10888,"protocol":"socks","settings":{"udp":true}}],
  "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":${PORT},
    "users":[{"id":"${UUIDS[0]}","encryption":"none","flow":"xtls-rprx-vision"}]}]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
      "serverName":"${SNI}","fingerprint":"chrome","publicKey":"${PUB}",
      "shortId":"${SHORTID}","spiderX":"/"}}}]
}
EOF
  setsid /usr/local/bin/xray run -config "$tdir/c.json" </dev/null >"$tdir/c.log" 2>&1 &
  local pid=$!
  sleep 6
  local got=""
  for _ in 1 2 3; do
    got="$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:10888 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$got" ] && break
    sleep 3
  done
  kill "$pid" 2>/dev/null || true
  rm -rf "$tdir"
  if [ "$got" = "$PUB_IP" ]; then
    log "self-test OK (egress IP = $got)"
    return 0
  fi
  warn "self-test FAILED (got '${got:-empty}', expected $PUB_IP)"
  warn "the mask domain '$SNI' may not relay REALITY. Try another, e.g. --sni www.apple.com"
  return 1
}

# =====================================================================
#  main
# =====================================================================
if [ "$UNINSTALL" = "1" ]; then
  uninstall
  exit $?
fi

if [ "$CHECK" = "1" ]; then
  check_setup
  exit $?
fi

if [ "$FIX" = "1" ]; then
  fix_setup
  exit $?
fi

if [ "$DRY_RUN" = "1" ]; then
  log "DRY RUN: no system changes"
  [ -x /usr/local/bin/xray ] && XB="/usr/local/bin/xray" || XB="xray"
  command -v "$XB" >/dev/null 2>&1 || die "xray not found; cannot dry-run key generation"
  out="$("$XB" x25519)"; PRIV="$(printf '%s\n' "$out" | awk -F': *' '/Private/{print $2}')"
  PUB="$(printf '%s\n' "$out" | awk -F': *' '/Public|Password/{print $2}')"
  SHORTID="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  gen_uuids
  [ "$WITH_MUX" = "1" ] && MUX_UUID="$(gen_uuid_one)"
  write_config "$WORKDIR/config.json"
  write_links
  write_client_config
  echo "--- sample config: $WORKDIR/config.json ---"
  echo "--- links ---"; cat "$WORKDIR/links.txt"
  exit 0
fi

install_xray
verify_sni || die "mask domain $SNI is not usable as REALITY dest"

LIVE_CFG="/usr/local/etc/xray/config.json"
mkdir -p /usr/local/etc/xray /var/log/xray

# Decide whether to reuse credentials from an existing install (idempotent re-run)
# or generate fresh ones. Reuse keeps client links valid; --force rotates everything.
if [ "$FORCE" = "1" ]; then
  log "force: generating new keys and UUIDs"
  gen_keys
  gen_uuids
  [ "$WITH_MUX" = "1" ] && MUX_UUID="$(gen_uuid_one)"
elif load_existing "$LIVE_CFG"; then
  PRIV="$EXIST_PRIV"
  SHORTID="$EXIST_SHORTID"
  PUB="$(derive_pub "$PRIV")"
  [ -n "$PUB" ] || die "could not derive public key from existing private key"
  # keep the requested client count, reusing existing UUIDs where possible
  gen_uuids
  local_i=0
  if [ "${#EXIST_UUIDS[@]}" -gt 0 ]; then
    for u in "${EXIST_UUIDS[@]}"; do
      [ "$local_i" -ge "$NCLIENTS" ] && break
      UUIDS[$local_i]="$u"
      local_i=$((local_i+1))
    done
  fi
  # reuse the existing mux user (or make one) when a mux profile is requested
  if [ "$WITH_MUX" = "1" ]; then
    MUX_UUID="${EXIST_MUX_UUID:-$(gen_uuid_one)}"
  fi
  log "existing config found: reusing REALITY key, shortId and ${#EXIST_UUIDS[@]} client UUID(s)"
  log "(run with --force to rotate keys/UUIDs and issue new links)"
else
  gen_keys
  gen_uuids
  [ "$WITH_MUX" = "1" ] && MUX_UUID="$(gen_uuid_one)"
fi

# back up an existing config
BACKUP=""
if [ -f "$LIVE_CFG" ]; then
  BACKUP="$WORKDIR/config.json.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$LIVE_CFG" "$BACKUP"
  log "backed up existing config to $BACKUP"
fi

# roll the previous config back (used if the new one fails the self-test)
rollback() {
  if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$LIVE_CFG"
    systemctl restart xray >/dev/null 2>&1 || true
    warn "restored previous config from $BACKUP and restarted xray"
  else
    warn "no previous config to restore; leaving generated config in place"
  fi
}

write_config "$LIVE_CFG"
chmod 755 /usr/local/etc/xray
chmod 644 /usr/local/etc/xray/config.json
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1 \
  || die "generated config failed xray -test"
log "config valid"

# xray -test runs as root and may create root-owned log files; fix ownership so the
# service (User=nobody) can write them.
chmod 755 /var/log/xray
rm -f /var/log/xray/error.log /var/log/xray/access.log
chown -R nobody:nogroup /var/log/xray 2>/dev/null || chown -R nobody /var/log/xray 2>/dev/null || true

write_unit
systemctl daemon-reload
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 3
if ! systemctl is-active --quiet xray; then
  rollback
  die "xray did not start; see: journalctl -u xray -n 50"
fi
log "xray active on tcp/${PORT}"

open_firewall
harden_network
write_links
write_client_config

if ! self_test; then
  warn "config is installed but the tunnel self-test failed."
  rollback
  warn "Inspect: journalctl -u xray -n 50 ; /var/log/xray/error.log"
  exit 2
fi

echo
log "DONE. Client links:"
cat "$WORKDIR/links.txt"
if command -v qrencode >/dev/null 2>&1; then
  echo; log "QR for ${NAME}-${PORT}:"
  qrencode -t ANSIUTF8 "$(head -n1 "$WORKDIR/links.txt")" || true
fi
echo
log "keys: priv=$(printf '%s' "$PRIV")  pub=$PUB  shortId=$SHORTID"
log "config: /usr/local/etc/xray/config.json   links: $WORKDIR/links.txt"
log "client config (vision + keepalive): $WORKDIR/client.json"
log "hardening: $SYSCTL_FILE  (tcp_mtu_probing=1, bbr, MSS clamp)"

