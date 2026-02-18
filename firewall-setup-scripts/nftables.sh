#!/bin/bash
#
# nftables.sh — Host firewall using nftables
#
# Our rules live in the "inet firewall" table, completely isolated
# from Docker's tables. Flushing/reloading does NOT destroy Docker's
# chains, so no Docker restart is needed on re-runs.
#
# Set management:
#   Sets are defined in the ruleset but populated from external sources.
#   The blocklist set is refreshed by cron via update-blocklist.sh.
#   To manually manage sets at runtime:
#     nft add element inet firewall blocklist { 1.2.3.4 }
#     nft delete element inet firewall blocklist { 1.2.3.4 }
#     nft list set inet firewall blocklist
#     nft flush set inet firewall blocklist
#
# First-time setup:
#   1. apt install nftables curl
#   2. Run this script
#   3. Test connectivity, then atrm the rollback job
#   4. Install /usr/local/sbin/update-blocklist.sh
#   5. Add cron: 0 */6 * * * /usr/local/sbin/update-blocklist.sh

set -euo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "Must be run as root user"
    exit 1
fi

#if ! command -v nft &>/dev/null; then
#    echo "nft not found — install with: apt install nftables"
#    exit 1
#fi

# --- Configuration ---
#CURRENT_HOME_IP=$(dig @localhost firecat.the-mcnultys.org | cut -f 4)
CURRENT_HOME_IP="73.137.239.99"
BLOCKLIST_URL="https://lists.blocklist.de/lists/all.txt"
BLOCKLIST_DIR="/var/lib/nftables"

# --- Rollback safety ---
if [ "${1:-}" == "norollback" ]; then
    echo "Skipping \"at\" job for auto-rollback"
else
    atjobid=$(echo "nft delete table inet firewall 2>/dev/null; iptables -F INPUT 2>/dev/null" | \
        at now + 2 minute 2>&1 | \
        grep -v '^warning' | cut -d " " -f 2)

    echo "If the new rules work, remove the \"at\" job using \"atq\" and"
    echo "\"atrm ${atjobid}\" or firewall rules will be flushed after 2 minutes"
    echo
    echo "To save rules permanently:"
    echo "  nft list table inet firewall > /etc/nftables.d/firewall.nft"
    echo
fi

# --- Clear legacy iptables INPUT rules (migration; doesn't touch Docker's FORWARD/NAT) ---
iptables -F INPUT 2>/dev/null || true

# --- Flush our table only (Docker's tables are untouched) ---
nft delete table inet firewall 2>/dev/null || true

# --- Apply rules ---
nft -f - <<EOF
table inet firewall {

    # ---------------------------------------------------------------
    # Sets — populated after table creation, reloadable at runtime
    # ---------------------------------------------------------------

    set home_ips {
        type ipv4_addr
        elements = { ${CURRENT_HOME_IP} }
    }

    set lonestar_ips {
        type ipv4_addr
        elements = { 205.166.94.30, 205.166.94.16 }
    }

    # Uncomment and populate as needed:
    # set juniper_ips {
    #     type ipv4_addr
    #     elements = { ... }
    # }
    # set gcp_ips {
    #     type ipv4_addr
    #     elements = { ... }
    # }

    set dns_block_ips {
        type ipv4_addr
        flags interval
        elements = {
            60.26.66.220,
            60.26.66.250,
            172.253.2.0/24,
            172.217.43.147,
            143.215.172.85
        }
    }

    # Blocklist — populated from blocklist.de after rules load
    # Supports ~30K+ entries efficiently via kernel-side hash table
    set blocklist {
        type ipv4_addr
        flags interval
        auto-merge
    }

    set home_tcp_ports {
        type inet_service
        elements = { 20, 21, 22, 53, 80, 443, 8888, 22000, 25972, 64624 }
    }

    set home_udp_ports {
        type inet_service
        elements = { 53, 500, 4500, 22000, 61798, 64624 }
    }

    # ---------------------------------------------------------------
    # Input chain
    # ---------------------------------------------------------------

    chain input {
        type filter hook input priority 0; policy drop;

        # --- Fast path ---
        iifname "lo" accept
        ct state established,related accept
        ct state invalid log prefix "invalid state: " level info drop

        # --- Blocklist (updated by cron) ---
        ip saddr @blocklist log prefix "blocklist denied: " level info drop

        # --- Trusted IP access ---

        # Home
        ip saddr @home_ips tcp dport @home_tcp_ports log prefix "policy accepted: " level info accept
        ip saddr @home_ips udp dport @home_udp_ports log prefix "policy accepted: " level info accept

        # Lonestar — SSH only
        ip saddr @lonestar_ips tcp dport 22 log prefix "policy accepted: " level info accept

        # Uncomment when populated:
        # ip saddr @juniper_ips tcp dport { 22, 8888, 64624 } log prefix "policy accepted: " level info accept
        # ip saddr @juniper_ips udp dport 64624 log prefix "policy accepted: " level info accept
        # ip saddr @gcp_ips tcp dport 22 log prefix "policy accepted: " level info accept

        # --- ICMP (allow essentials, rate-limit echo) ---
        icmp type { destination-unreachable, time-exceeded } accept
        icmp type echo-request limit rate 5/second burst 10 packets accept
        icmp type echo-request drop

        # --- DNS protection ---

        # Block known abusers
        ip saddr @dns_block_ips udp dport 53 log prefix "policy denied: " level info drop

        # Rate-limit DNS queries: 4/min per source IP
        udp dport 53 meter dns-rate { ip saddr limit rate 4/minute burst 4 packets } accept
        udp dport 53 log prefix "dns rate denied: " level info drop

        # --- TCP anomaly protection ---

        # New connection without SYN
        ct state new tcp flags & (fin | syn | rst | ack) != syn log prefix "policy denied: " level info drop

        # IP fragments
        ip frag-off & 0x1fff != 0 log prefix "policy denied: " level info drop

        # Xmas scan (FIN+PSH+URG)
        tcp flags & (fin | syn | rst | psh | ack | urg) == (fin | psh | urg) log prefix "policy denied: " level info drop
        # All flags set
        tcp flags & (fin | syn | rst | psh | ack | urg) == (fin | syn | rst | psh | ack | urg) log prefix "policy denied: " level info drop
        # Null scan (no flags)
        tcp flags & (fin | syn | rst | psh | ack | urg) == 0x0 log prefix "policy denied: " level info drop
        # SYN+RST
        tcp flags & (syn | rst) == (syn | rst) log prefix "policy denied: " level info drop
        # SYN+FIN
        tcp flags & (fin | syn) == (fin | syn) log prefix "policy denied: " level info drop
        # FIN without ACK
        tcp flags & (fin | ack) == fin log prefix "policy denied: " level info drop
        # FIN+SYN+RST+ACK+URG (missing only PSH)
        tcp flags & (fin | syn | rst | psh | ack | urg) == (fin | syn | rst | ack | urg) log prefix "policy denied: " level info drop

        # --- Docker-proxied web services (open to all, SYN rate-limited) ---
        tcp dport { 80, 443 } ct state new meter web-syn { ip saddr limit rate 25/second burst 50 packets } accept
        tcp dport { 80, 443 } ct state new log prefix "syn flood: " level info drop
        tcp dport { 80, 443 } accept

        # --- Catch-all ---
        log prefix "policy denied: " level info drop
    }
}
EOF

# --- Docker DNAT workaround ---
if iptables -t nat -S DOCKER &>/dev/null; then
    iptables -t nat -D DOCKER -p tcp --dport 443 -j RETURN 2>/dev/null || true
    iptables -t nat -D DOCKER -p tcp --dport 80 -j RETURN 2>/dev/null || true
    iptables -t nat -I DOCKER 1 -p tcp --dport 443 -j RETURN
    iptables -t nat -I DOCKER 1 -p tcp --dport 80 -j RETURN
fi

# --- Load blocklist ---
mkdir -p "$BLOCKLIST_DIR"
echo -n "Loading blocklist... "
TMPFILE=$(mktemp)
if curl -sf --max-time 30 "$BLOCKLIST_URL" -o "$TMPFILE"; then
    # Cache the raw list for offline reloads
    cp "$TMPFILE" "${BLOCKLIST_DIR}/blocklist.txt"
    COUNT=$(grep -coE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPFILE")
    nft flush set inet firewall blocklist
    grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPFILE" | sort -u | \
        xargs -n 5000 | sed 's/ /, /g' | \
        while IFS= read -r chunk; do
            echo "add element inet firewall blocklist { $chunk }" | nft -f -
        done
    echo "${COUNT} IPs loaded."
elif [ -f "${BLOCKLIST_DIR}/blocklist.txt" ]; then
    # Offline fallback — use cached copy
    COUNT=$(grep -coE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${BLOCKLIST_DIR}/blocklist.txt")
    nft flush set inet firewall blocklist
    grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${BLOCKLIST_DIR}/blocklist.txt" | sort -u | \
        xargs -n 5000 | sed 's/ /, /g' | \
        while IFS= read -r chunk; do
            echo "add element inet firewall blocklist { $chunk }" | nft -f -
        done
    echo "${COUNT} IPs loaded (cached)."
else
    echo "download failed and no cache, skipping."
fi
rm -f "$TMPFILE"

echo "Firewall rules applied."

