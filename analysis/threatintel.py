#!/usr/bin/env bash
# =============================================================================
# SIB Threat Intelligence Feed Updater
# Place at: /app/threatintel/update-feeds.sh  (already COPY'd by Dockerfile)
#
# Usage:
#   /app/threatintel/update-feeds.sh            # download all feeds
#   docker exec analyser /app/threatintel/update-feeds.sh   # from host
#
# Environment variables:
#   FEED_TIMEOUT      curl timeout in seconds        (default: 30)
#   FEED_MIN_IPS      minimum IPs to keep a feed     (default: 1)
#   MAX_RULES_IPS     cap for Falco rule IP list      (default: 5000)
#   THREATFOX_API_KEY abuse.ch API key for ThreatFox  (optional but recommended)
#                     Get a free key at https://auth.abuse.ch/
#
# Cron (every 6 hours, then hot-reload the API):
#   0 */6 * * * /app/threatintel/update-feeds.sh \
#     && curl -s -X POST http://localhost:5000/api/threatintel/reload
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEEDS_DIR="${SCRIPT_DIR}/feeds"
COMBINED="${FEEDS_DIR}/combined_blocklist.txt"

TIMEOUT="${FEED_TIMEOUT:-30}"
# NOTE: Feodo Tracker intentionally has very few entries (only confirmed active
# C2s). Default MIN_IPS=1 so it never gets skipped on quiet days.
MIN_IPS="${FEED_MIN_IPS:-1}"
MAX_RULES_IPS="${MAX_RULES_IPS:-5000}"

mkdir -p "${FEEDS_DIR}"

# ── Terminal colours (gracefully disabled if not a tty) ──────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m' YELLOW='\033[1;33m' GREEN='\033[0;32m'
  CYAN='\033[0;36m' BOLD='\033[1m' RESET='\033[0m'
else
  RED='' YELLOW='' GREEN='' CYAN='' BOLD='' RESET=''
fi

log()  { echo -e "${CYAN}[threatintel]${RESET} $*"; }
ok()   { echo -e "${GREEN}[threatintel] ✓${RESET} $*"; }
warn() { echo -e "${YELLOW}[threatintel] ⚠${RESET} $*"; }

# =============================================================================
# download_feed <name> <url> [extract_cmd]
#   Writes plain IPv4 addresses (one per line) to feeds/<name>.txt
#   Filters out RFC1918/loopback — these should never be in public feeds.
# =============================================================================
download_feed() {
    local name="$1" url="$2" extract_cmd="${3:-cat}"
    local out="${FEEDS_DIR}/${name}.txt"
    local tmp; tmp="$(mktemp)"

    log "Fetching ${name} ..."
    if ! curl -fsSL --max-time "${TIMEOUT}" --compressed \
         -A "SIB-ThreatIntel/1.0" "${url}" -o "${tmp}" 2>/dev/null; then
        warn "${name}: download failed — skipping"
        rm -f "${tmp}"; return 1
    fi

    eval "${extract_cmd}" < "${tmp}" \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | grep -v '^0\.\|^127\.\|^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[0-1]\.\|^192\.168\.' \
        | sort -u > "${out}" || true
    rm -f "${tmp}"

    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt "${MIN_IPS}" ]]; then
        warn "${name}: ${count} IPs (threshold ${MIN_IPS}) — skipping"
        rm -f "${out}"; return 1
    fi
    ok "${name}: ${count} IPs"
}

# =============================================================================
# Individual feed functions
# =============================================================================

fetch_feodotracker() {
    # Feodo Tracker "recommended" blocklist — active C2s seen in past 30 days.
    # This list has hundreds of entries; the "ipblocklist.txt" (IPs only, no
    # 30-day window) may have as few as 1–6 entries on quiet days.
    download_feed "feodotracker" \
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
}

fetch_sslbl() {
    # SSLBL plain-text IP list was DEPRECATED on 2025-01-03 and is now empty.
    # Replaced with the SSLBL CSV (still maintained), extracting the dst_ip column.
    # CSV format: "first_seen","dst_ip","dst_port","c2_status","last_online","malware"
    local out="${FEEDS_DIR}/sslbl.txt"
    local tmp; tmp="$(mktemp)"
    log "Fetching sslbl (CSV) ..."
    if ! curl -fsSL --max-time "${TIMEOUT}" \
         -A "SIB-ThreatIntel/1.0" \
         "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv" \
         -o "${tmp}" 2>/dev/null; then
        warn "sslbl: download failed — skipping"; rm -f "${tmp}"; return 1
    fi
    # Extract IP column from CSV (skip comment lines starting with #)
    grep -v '^#' "${tmp}" \
        | cut -d',' -f2 \
        | tr -d '"' \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | grep -v '^0\.\|^127\.\|^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[0-1]\.\|^192\.168\.' \
        | sort -u > "${out}" || true
    rm -f "${tmp}"
    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt "${MIN_IPS}" ]]; then
        warn "sslbl: ${count} IPs (threshold ${MIN_IPS}) — skipping"; rm -f "${out}"; return 1
    fi
    ok "sslbl: ${count} IPs (from CSV)"
}

fetch_threatfox() {
    # ThreatFox — abuse.ch community IOC platform (replaces SSLBL as C2 feed).
    # Requires a free Auth-Key: https://auth.abuse.ch/
    # Set THREATFOX_API_KEY in your environment or Docker secret.
    local api_key="${THREATFOX_API_KEY:-}"
    if [[ -z "${api_key}" ]]; then
        warn "threatfox: THREATFOX_API_KEY not set — skipping"
        warn "  Get a free key at https://auth.abuse.ch/ then set:"
        warn "  THREATFOX_API_KEY=your-key in your .env / Docker Compose file"
        return 1
    fi

    local out="${FEEDS_DIR}/threatfox.txt"
    local tmp; tmp="$(mktemp)"
    log "Fetching threatfox (recent IP IOCs) ..."

    # Query ThreatFox API for recent ip:port IOCs (last 7 days)
    if ! curl -fsSL --max-time "${TIMEOUT}" \
         -H "Auth-Key: ${api_key}" \
         -H "Content-Type: application/json" \
         -d '{"query":"get_iocs","days":7}' \
         "https://threatfox-api.abuse.ch/api/v1/" \
         -o "${tmp}" 2>/dev/null; then
        warn "threatfox: API request failed — skipping"
        rm -f "${tmp}"; return 1
    fi

    # Parse JSON: extract ioc values where ioc_type == "ip:port", strip port
    # Uses python3 (available in the container) for reliable JSON parsing
    python3 - "${tmp}" "${out}" << 'PYEOF'
import json, sys, re

src, dst = sys.argv[1], sys.argv[2]
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
PRIV = re.compile(r'^(0\.|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)')

ips = set()
try:
    with open(src) as f:
        data = json.load(f)
    for ioc in data.get("data", []) or []:
        if ioc.get("ioc_type") in ("ip:port", "ip"):
            raw = ioc.get("ioc", "")
            for ip in IPV4_RE.findall(raw):
                if not PRIV.match(ip):
                    ips.add(ip)
except Exception as e:
    print(f"parse error: {e}", file=sys.stderr)

with open(dst, "w") as f:
    f.write("\n".join(sorted(ips)))
    if ips:
        f.write("\n")

print(f"extracted {len(ips)} IPs", file=sys.stderr)
PYEOF

    rm -f "${tmp}"
    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt "${MIN_IPS}" ]]; then
        warn "threatfox: ${count} IPs — skipping"; rm -f "${out}"; return 1
    fi
    ok "threatfox: ${count} IPs"
}

fetch_emerging_threats() {
    download_feed "et_compromised" \
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
}

fetch_spamhaus_drop() {
    # Spamhaus DROP uses CIDR notation — stored separately, not combined with plain IPs
    local out="${FEEDS_DIR}/spamhaus_drop.txt"
    local tmp; tmp="$(mktemp)"
    log "Fetching spamhaus_drop ..."
    if ! curl -fsSL --max-time "${TIMEOUT}" \
         "https://www.spamhaus.org/drop/drop.txt" -o "${tmp}" 2>/dev/null; then
        warn "spamhaus_drop: download failed — skipping"; rm -f "${tmp}"; return 1
    fi
    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b' "${tmp}" \
        | sort -u > "${out}" || true
    rm -f "${tmp}"
    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt 5 ]]; then
        warn "spamhaus_drop: only ${count} CIDRs — skipping"; return 1
    fi
    ok "spamhaus_drop: ${count} CIDR blocks"
}

fetch_blocklist_de_ssh() {
    download_feed "blocklist_ssh" "https://lists.blocklist.de/lists/ssh.txt"
}

fetch_blocklist_de_all() {
    download_feed "blocklist_all" "https://lists.blocklist.de/lists/all.txt"
}

fetch_ci_army() {
    download_feed "ci_army" "https://cinsscore.com/list/ci-badguys.txt"
}

fetch_tor_exit_nodes() {
    download_feed "tor_exit_nodes" "https://check.torproject.org/torbulkexitlist"
}

# =============================================================================
# Combine all plain-IP feeds into one deduplicated list
# =============================================================================
combine_feeds() {
    log "Combining feeds → ${COMBINED}"
    > "${COMBINED}"
    for f in "${FEEDS_DIR}"/*.txt; do
        [[ "${f}" == "${COMBINED}" ]] && continue
        [[ "${f}" == *spamhaus_drop* ]] && continue
        grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${f}" >> "${COMBINED}" 2>/dev/null || true
    done
    sort -u -o "${COMBINED}" "${COMBINED}"
    local total; total=$(wc -l < "${COMBINED}" | tr -d ' ')
    ok "Combined blocklist: ${total} unique IPs"
}

# =============================================================================
# Generate Falco threat intel rules
# =============================================================================
generate_falco_rules() {
    local rules_out="${SCRIPT_DIR}/falco_threatintel_rules.yaml"
    log "Generating Falco rules → ${rules_out}"

    local combined_count=0
    [[ -f "${COMBINED}" ]] && combined_count=$(wc -l < "${COMBINED}" | tr -d ' ')

    local ip_list=""
    if [[ -f "${COMBINED}" && "${combined_count}" -gt 0 ]]; then
        ip_list=$(head -n "${MAX_RULES_IPS}" "${COMBINED}" | tr '\n' ',' | sed 's/,$//')
    fi

    # C2 IPs from feodo + sslbl + threatfox combined
    local c2_tmp; c2_tmp="$(mktemp)"
    for f in "${FEEDS_DIR}/feodotracker.txt" "${FEEDS_DIR}/sslbl.txt" "${FEEDS_DIR}/threatfox.txt"; do
        [[ -f "${f}" ]] && cat "${f}" >> "${c2_tmp}"
    done
    local c2_ips=""
    if [[ -s "${c2_tmp}" ]]; then
        c2_ips=$(sort -u "${c2_tmp}" | head -n 1000 | tr '\n' ',' | sed 's/,$//')
    fi
    rm -f "${c2_tmp}"

    cat > "${rules_out}" <<YAML
# ============================================================================
# SIB Threat Intelligence Falco Rules
# Auto-generated by /app/threatintel/update-feeds.sh
# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# Combined IPs: ${combined_count} (rules capped at ${MAX_RULES_IPS})
# ============================================================================

- macro: outbound_connection
  condition: >
    evt.type in (connect, sendto, sendmsg) and evt.dir = < and
    fd.typechar = 4 and fd.connected = true

- macro: inbound_connection
  condition: evt.type in (accept, accept4) and evt.dir = <

- macro: c2_ports
  condition: >
    fd.rport in (4444, 4445, 1337, 31337, 8080, 8443, 443, 80,
                 6667, 6668, 6669, 6697, 9001, 9030, 3389, 5900)

- macro: mining_pool_ports
  condition: >
    fd.rport in (3333, 4444, 8333, 9999, 14444, 14433, 45700, 45560, 7777, 3032)

- macro: threatintel_combined_ip
  condition: fd.rip in (${ip_list:-"0.0.0.0"})

- macro: threatintel_c2_ip
  condition: fd.rip in (${c2_ips:-"0.0.0.0"})

- rule: Connection to Threat Intel IP (Outbound)
  desc: Outbound connection to a blocklisted IP. May indicate C2 or data exfiltration.
  condition: outbound_connection and threatintel_combined_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Outbound connection to blocklisted IP
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel)
  priority: WARNING
  tags: [network, threatintel, mitre_command_and_control]

- rule: Connection to Known C2 Server
  desc: Connection to an active botnet C2 (Feodo/SSLBL/ThreatFox). High confidence IOC.
  condition: outbound_connection and threatintel_c2_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Connection to known C2 server
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,c2)
  priority: ERROR
  tags: [network, threatintel, c2, mitre_command_and_control]

- rule: Connection to Threat Intel IP on C2 Port
  desc: Blocklisted IP contacted on a known C2 port. Critical priority.
  condition: outbound_connection and threatintel_combined_ip and c2_ports and not fd.rip in (127.0.0.1, ::1)
  output: >
    Blocklisted IP on C2 port
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,c2)
  priority: CRITICAL
  tags: [network, threatintel, c2, mitre_command_and_control]

- rule: Connection to Crypto Mining Pool
  desc: Outbound connection on a port used by crypto mining pools. Indicates cryptojacking.
  condition: outbound_connection and mining_pool_ports and not fd.rip in (127.0.0.1, ::1)
  output: >
    Possible crypto mining connection
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,cryptomining)
  priority: CRITICAL
  tags: [network, threatintel, cryptomining, mitre_impact]

- rule: Connection from Threat Intel IP (Inbound)
  desc: Inbound connection accepted from a blocklisted IP.
  condition: inbound_connection and threatintel_combined_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Inbound connection from blocklisted IP
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.rip:%fd.rport dst_port=%fd.lport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel)
  priority: WARNING
  tags: [network, threatintel, mitre_initial_access]
YAML

    ok "Falco rules written → ${rules_out}"
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}━━━ Feed Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    for f in "${FEEDS_DIR}"/*.txt; do
        [[ -f "${f}" ]] || continue
        printf "  %-32s %6s entries\n" "$(basename "${f}" .txt)" "$(wc -l < "${f}" | tr -d ' ')"
    done
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo "  Reload the API without restart:"
    echo -e "  ${GREEN}curl -s -X POST http://localhost:5000/api/threatintel/reload${RESET}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo -e "${BOLD}🛡️  SIB Threat Intelligence Feed Updater${RESET}"
    echo "   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    local failed=0
    fetch_feodotracker     || ((failed++)) || true
    fetch_sslbl            || ((failed++)) || true
    fetch_threatfox        || ((failed++)) || true   # skipped if no API key
    fetch_emerging_threats || ((failed++)) || true
    fetch_spamhaus_drop    || ((failed++)) || true
    fetch_blocklist_de_ssh || ((failed++)) || true
    fetch_blocklist_de_all || ((failed++)) || true
    fetch_ci_army          || ((failed++)) || true
    fetch_tor_exit_nodes   || ((failed++)) || true

    combine_feeds
    generate_falco_rules
    print_summary

    [[ "${failed}" -gt 0 ]] && { warn "${failed} feed(s) failed or were skipped"; }
    exit 0   # never fail the whole run due to individual feed issues
}

main "$@"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEEDS_DIR="${SCRIPT_DIR}/feeds"
COMBINED="${FEEDS_DIR}/combined_blocklist.txt"

TIMEOUT="${FEED_TIMEOUT:-30}"
MIN_IPS="${FEED_MIN_IPS:-10}"
MAX_RULES_IPS="${MAX_RULES_IPS:-5000}"

mkdir -p "${FEEDS_DIR}"

# ── Terminal colours (gracefully disabled if not a tty) ──────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m' YELLOW='\033[1;33m' GREEN='\033[0;32m'
  CYAN='\033[0;36m' BOLD='\033[1m' RESET='\033[0m'
else
  RED='' YELLOW='' GREEN='' CYAN='' BOLD='' RESET=''
fi

log()  { echo -e "${CYAN}[threatintel]${RESET} $*"; }
ok()   { echo -e "${GREEN}[threatintel] ✓${RESET} $*"; }
warn() { echo -e "${YELLOW}[threatintel] ⚠${RESET} $*"; }

# =============================================================================
# download_feed <name> <url> [extract_cmd]
#   Writes plain IPv4 addresses (one per line) to feeds/<name>.txt
#   Filters out RFC1918/loopback — public blocklists should never contain them.
# =============================================================================
download_feed() {
    local name="$1" url="$2" extract_cmd="${3:-cat}"
    local out="${FEEDS_DIR}/${name}.txt"
    local tmp; tmp="$(mktemp)"

    log "Fetching ${name} ..."
    if ! curl -fsSL --max-time "${TIMEOUT}" --compressed \
         -A "SIB-ThreatIntel/1.0" "${url}" -o "${tmp}" 2>/dev/null; then
        warn "${name}: download failed — skipping"
        rm -f "${tmp}"; return 1
    fi

    eval "${extract_cmd}" < "${tmp}" \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | grep -v '^0\.\|^127\.\|^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[0-1]\.\|^192\.168\.' \
        | sort -u > "${out}" || true
    rm -f "${tmp}"

    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt "${MIN_IPS}" ]]; then
        warn "${name}: only ${count} IPs (threshold ${MIN_IPS}) — skipping"
        rm -f "${out}"; return 1
    fi
    ok "${name}: ${count} IPs"
}

# =============================================================================
# Individual feed functions
# =============================================================================

fetch_feodotracker() {
    download_feed "feodotracker" \
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
}

fetch_sslbl() {
    download_feed "sslbl" \
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
}

fetch_emerging_threats() {
    download_feed "et_compromised" \
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
}

fetch_spamhaus_drop() {
    # Spamhaus DROP uses CIDR notation — stored separately, not combined with plain IPs
    local out="${FEEDS_DIR}/spamhaus_drop.txt"
    local tmp; tmp="$(mktemp)"
    log "Fetching spamhaus_drop ..."
    if ! curl -fsSL --max-time "${TIMEOUT}" \
         "https://www.spamhaus.org/drop/drop.txt" -o "${tmp}" 2>/dev/null; then
        warn "spamhaus_drop: download failed — skipping"; rm -f "${tmp}"; return 1
    fi
    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b' "${tmp}" \
        | sort -u > "${out}" || true
    rm -f "${tmp}"
    local count; count=$(wc -l < "${out}" | tr -d ' ')
    if [[ "${count}" -lt 5 ]]; then
        warn "spamhaus_drop: only ${count} CIDRs — skipping"; return 1
    fi
    ok "spamhaus_drop: ${count} CIDR blocks"
}

fetch_blocklist_de_ssh() {
    download_feed "blocklist_ssh" "https://lists.blocklist.de/lists/ssh.txt"
}

fetch_blocklist_de_all() {
    download_feed "blocklist_all" "https://lists.blocklist.de/lists/all.txt"
}

fetch_ci_army() {
    download_feed "ci_army" "https://cinsscore.com/list/ci-badguys.txt"
}

fetch_tor_exit_nodes() {
    download_feed "tor_exit_nodes" "https://check.torproject.org/torbulkexitlist"
}

# =============================================================================
# Combine all plain-IP feeds into one deduplicated list
# =============================================================================
combine_feeds() {
    log "Combining feeds → ${COMBINED}"
    > "${COMBINED}"
    for f in "${FEEDS_DIR}"/*.txt; do
        [[ "${f}" == "${COMBINED}" ]] && continue
        [[ "${f}" == *spamhaus_drop* ]] && continue
        grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${f}" >> "${COMBINED}" 2>/dev/null || true
    done
    sort -u -o "${COMBINED}" "${COMBINED}"
    local total; total=$(wc -l < "${COMBINED}" | tr -d ' ')
    ok "Combined blocklist: ${total} unique IPs"
}

# =============================================================================
# Generate Falco threat intel rules
# =============================================================================
generate_falco_rules() {
    local rules_out="${SCRIPT_DIR}/falco_threatintel_rules.yaml"
    log "Generating Falco rules → ${rules_out}"

    local combined_count=0
    [[ -f "${COMBINED}" ]] && combined_count=$(wc -l < "${COMBINED}" | tr -d ' ')

    local ip_list=""
    if [[ -f "${COMBINED}" && "${combined_count}" -gt 0 ]]; then
        ip_list=$(head -n "${MAX_RULES_IPS}" "${COMBINED}" | tr '\n' ',' | sed 's/,$//')
    fi

    local feodo_ips="" sslbl_ips=""
    [[ -f "${FEEDS_DIR}/feodotracker.txt" ]] && \
        feodo_ips=$(head -n 500 "${FEEDS_DIR}/feodotracker.txt" | tr '\n' ',' | sed 's/,$//')
    [[ -f "${FEEDS_DIR}/sslbl.txt" ]] && \
        sslbl_ips=$(head -n 500 "${FEEDS_DIR}/sslbl.txt" | tr '\n' ',' | sed 's/,$//')

    cat > "${rules_out}" <<YAML
# ============================================================================
# SIB Threat Intelligence Falco Rules
# Auto-generated by /app/threatintel/update-feeds.sh
# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# Combined IPs: ${combined_count} (rules capped at ${MAX_RULES_IPS})
# To enable: cp ${rules_out} /path/to/falco/rules/
# ============================================================================

- macro: outbound_connection
  condition: >
    evt.type in (connect, sendto, sendmsg) and evt.dir = < and
    fd.typechar = 4 and fd.connected = true

- macro: inbound_connection
  condition: evt.type in (accept, accept4) and evt.dir = <

- macro: c2_ports
  condition: >
    fd.rport in (4444, 4445, 1337, 31337, 8080, 8443, 443, 80,
                 6667, 6668, 6669, 6697, 9001, 9030, 3389, 5900)

- macro: mining_pool_ports
  condition: >
    fd.rport in (3333, 4444, 8333, 9999, 14444, 14433, 45700, 45560, 7777, 3032)

- macro: threatintel_combined_ip
  condition: fd.rip in (${ip_list:-"0.0.0.0"})

- macro: threatintel_c2_ip
  condition: >
    fd.rip in (${feodo_ips:-"0.0.0.0"}) or
    fd.rip in (${sslbl_ips:-"0.0.0.0"})

- rule: Connection to Threat Intel IP (Outbound)
  desc: Outbound connection to a blocklisted IP. May indicate C2 or data exfiltration.
  condition: outbound_connection and threatintel_combined_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Outbound connection to blocklisted IP
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel)
  priority: WARNING
  tags: [network, threatintel, mitre_command_and_control]

- rule: Connection to Known C2 Server
  desc: Connection to an active botnet C2 server (Feodo/SSLBL). High confidence IOC.
  condition: outbound_connection and threatintel_c2_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Connection to known C2 server
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,c2)
  priority: ERROR
  tags: [network, threatintel, c2, mitre_command_and_control]

- rule: Connection to Threat Intel IP on C2 Port
  desc: Blocklisted IP contacted on a known C2 port. Critical priority.
  condition: outbound_connection and threatintel_combined_ip and c2_ports and not fd.rip in (127.0.0.1, ::1)
  output: >
    Blocklisted IP on C2 port
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,c2)
  priority: CRITICAL
  tags: [network, threatintel, c2, mitre_command_and_control]

- rule: Connection to Crypto Mining Pool
  desc: Outbound connection on a port used by crypto mining pools. Indicates cryptojacking.
  condition: outbound_connection and mining_pool_ports and not fd.rip in (127.0.0.1, ::1)
  output: >
    Possible crypto mining connection
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.lip:%fd.lport dst=%fd.rip:%fd.rport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel,cryptomining)
  priority: CRITICAL
  tags: [network, threatintel, cryptomining, mitre_impact]

- rule: Connection from Threat Intel IP (Inbound)
  desc: Inbound connection accepted from a blocklisted IP.
  condition: inbound_connection and threatintel_combined_ip and not fd.rip in (127.0.0.1, ::1)
  output: >
    Inbound connection from blocklisted IP
    (command=%proc.cmdline pid=%proc.pid user=%user.name uid=%user.uid
     container=%container.name image=%container.image.repository
     src=%fd.rip:%fd.rport dst_port=%fd.lport
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name tags=threatintel)
  priority: WARNING
  tags: [network, threatintel, mitre_initial_access]
YAML

    ok "Falco rules written → ${rules_out}"
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}━━━ Feed Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    for f in "${FEEDS_DIR}"/*.txt; do
        [[ -f "${f}" ]] || continue
        printf "  %-30s %6s entries\n" "$(basename "${f}" .txt)" "$(wc -l < "${f}" | tr -d ' ')"
    done
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo "  Reload the API without restart:"
    echo -e "  ${GREEN}curl -s -X POST http://localhost:5000/api/threatintel/reload${RESET}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo -e "${BOLD}🛡️  SIB Threat Intelligence Feed Updater${RESET}"
    echo "   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    local failed=0
    fetch_feodotracker     || ((failed++)) || true
    fetch_sslbl            || ((failed++)) || true
    fetch_emerging_threats || ((failed++)) || true
    fetch_spamhaus_drop    || ((failed++)) || true
    fetch_blocklist_de_ssh || ((failed++)) || true
    fetch_blocklist_de_all || ((failed++)) || true
    fetch_ci_army          || ((failed++)) || true
    fetch_tor_exit_nodes   || ((failed++)) || true

    combine_feeds
    generate_falco_rules
    print_summary

    [[ "${failed}" -gt 0 ]] && { warn "${failed} feed(s) failed"; exit 1; }
    exit 0
}

main "$@"
