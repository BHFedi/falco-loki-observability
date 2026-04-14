#!/usr/bin/env bash
# =============================================================================
# Threat Intelligence IP Lookup
# Usage: /app/threatintel/lookup-ip.sh <IP> [<IP> ...]
#        docker exec analyser /app/threatintel/lookup-ip.sh 185.220.101.1
# Exits 1 if any IP is malicious (useful in CI/CD gates).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEEDS_DIR="${SCRIPT_DIR}/feeds"

if [ -t 1 ]; then
  RED='\033[0;31m' YELLOW='\033[1;33m' GREEN='\033[0;32m'
  CYAN='\033[0;36m' BOLD='\033[1m' GRAY='\033[0;90m' RESET='\033[0m'
else
  RED='' YELLOW='' GREEN='' CYAN='' BOLD='' GRAY='' RESET=''
fi

usage() {
    echo "Usage: $0 <IP_ADDRESS> [<IP_ADDRESS> ...]"
    echo "  Check one or more IPs against all threat intelligence feeds."
    echo ""
    echo "Examples:"
    echo "  $0 185.220.101.1"
    echo "  $0 192.168.1.1 45.33.32.156"
    exit 1
}

[[ $# -lt 1 ]] && usage

if [[ ! -d "${FEEDS_DIR}" ]] || [[ -z "$(ls "${FEEDS_DIR}"/*.txt 2>/dev/null || true)" ]]; then
    echo -e "${RED}✗ No feeds found in ${FEEDS_DIR}${RESET}"
    echo "  Run: /app/threatintel/update-feeds.sh"
    exit 1
fi

declare -A FEED_LABELS=(
    [feodotracker]="Feodo Tracker      (banking trojans / botnet C2)"
    [sslbl]="SSL Blacklist       (malware C2 via SSL certs)"
    [et_compromised]="Emerging Threats   (compromised hosts)"
    [blocklist_ssh]="Blocklist.de SSH   (SSH bruteforce)"
    [blocklist_all]="Blocklist.de All   (all attack types)"
    [ci_army]="CINSscore CI Army  (composite threat intel)"
    [tor_exit_nodes]="Tor Exit Nodes     (anonymization)"
)

declare -A FEED_SEVERITY=(
    [feodotracker]="${RED}CRITICAL${RESET}"
    [sslbl]="${RED}CRITICAL${RESET}"
    [et_compromised]="${YELLOW}HIGH${RESET}"
    [blocklist_ssh]="${YELLOW}MEDIUM${RESET}"
    [blocklist_all]="${YELLOW}MEDIUM${RESET}"
    [ci_army]="${YELLOW}HIGH${RESET}"
    [tor_exit_nodes]="${CYAN}INFO${RESET}"
)

check_freshness() {
    local max_age_h=25
    for f in "${FEEDS_DIR}"/*.txt; do
        [[ -f "${f}" ]] || continue
        local age_h=$(( ( $(date +%s) - $(date -r "${f}" +%s 2>/dev/null || echo 0) ) / 3600 ))
        if [[ "${age_h}" -gt "${max_age_h}" ]]; then
            echo -e "${YELLOW}⚠  Feeds may be stale (oldest: ${age_h}h) — run update-feeds.sh${RESET}"
            echo ""
            return
        fi
    done
}

lookup_single() {
    local ip="$1"
    local found=0
    local c2_hit=0

    echo ""
    echo -e "${BOLD}━━━ ${CYAN}${ip}${RESET}${BOLD} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    for feed_file in "${FEEDS_DIR}"/*.txt; do
        [[ -f "${feed_file}" ]] || continue
        local stem; stem="$(basename "${feed_file}" .txt)"
        [[ "${stem}" == "combined_blocklist" || "${stem}" == "spamhaus_drop" ]] && continue

        if grep -qxF "${ip}" "${feed_file}" 2>/dev/null; then
            local label="${FEED_LABELS[${stem}]:-${stem}}"
            local sev="${FEED_SEVERITY[${stem}]:-${YELLOW}MEDIUM${RESET}}"
            echo -e "  ${RED}⚠  FOUND${RESET}  ${label}  [${sev}]"
            [[ "${stem}" == "feodotracker" || "${stem}" == "sslbl" ]] && c2_hit=1
            ((found++)) || true
        fi
    done

    # Spamhaus CIDR check (simple /8 /16 /24)
    if [[ -f "${FEEDS_DIR}/spamhaus_drop.txt" ]]; then
        local a b c d; IFS='.' read -r a b c d <<< "${ip}"
        while IFS= read -r cidr; do
            [[ "${cidr}" =~ ^[#;]|^$ ]] && continue
            local net mask; net="${cidr%%/*}"; mask="${cidr##*/}"
            local na nb nc; IFS='.' read -r na nb nc _ <<< "${net}"
            case "${mask}" in
                8)  [[ "${a}" -eq "${na}" ]] && \
                        { echo -e "  ${RED}⚠  FOUND${RESET}  Spamhaus DROP (${cidr}) [${YELLOW}HIGH${RESET}]"; ((found++)) || true; break; } ;;
                16) [[ "${a}" -eq "${na}" && "${b}" -eq "${nb}" ]] && \
                        { echo -e "  ${RED}⚠  FOUND${RESET}  Spamhaus DROP (${cidr}) [${YELLOW}HIGH${RESET}]"; ((found++)) || true; break; } ;;
                24) [[ "${a}" -eq "${na}" && "${b}" -eq "${nb}" && "${c}" -eq "${nc}" ]] && \
                        { echo -e "  ${RED}⚠  FOUND${RESET}  Spamhaus DROP (${cidr}) [${YELLOW}HIGH${RESET}]"; ((found++)) || true; break; } ;;
            esac
        done < "${FEEDS_DIR}/spamhaus_drop.txt"
    fi

    echo ""
    if [[ "${found}" -gt 0 ]]; then
        echo -e "  ${RED}🚨 MALICIOUS — found in ${found} feed(s)${RESET}"
        if [[ "${c2_hit}" -eq 1 ]]; then
            echo -e "  ${RED}${BOLD}   CONFIRMED C2 SERVER — isolate affected hosts immediately${RESET}"
        fi
        echo ""
        echo -e "  ${BOLD}Recommended actions:${RESET}"
        echo -e "    ${YELLOW}•${RESET} Block at firewall / security group"
        echo -e "    ${YELLOW}•${RESET} Search Loki: ${GRAY}{source=\"syscall\"} |= \"${ip}\"${RESET}"
        echo -e "    ${YELLOW}•${RESET} Review lateral movement on affected hosts"
    else
        echo -e "  ${GREEN}✓  CLEAN — not found in any feed${RESET}"
        echo -e "  ${GRAY}(Feeds age: run update-feeds.sh to refresh)${RESET}"
    fi

    echo ""
    return "${found}"
}

# ── Main ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}🛡️  Threat Intelligence Lookup${RESET}"
check_freshness

overall=0
for ip in "$@"; do
    lookup_single "${ip}" || ((overall++)) || true
done

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
[[ "${overall}" -gt 0 ]] && exit 1
exit 0
