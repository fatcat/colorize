#!/usr/bin/env bash
#
# colorize.sh - Parse iptables/netfilter log lines into color-coded,
#               fixed-width column output with GeoIP country lookups.
#
# Usage: cat /var/log/syslog | ./colorize.sh [OPTIONS]
#        tail -f /var/log/syslog | ./colorize.sh [OPTIONS]
#
# Options:
#   -u, --show-unmatched  Print non-matching lines as-is (default: skip)
#   -n, --no-color        Disable ANSI color codes
#   -h, --help            Show usage information

set -euo pipefail

# --- Defaults ---
SHOW_UNMATCHED=false
USE_COLOR=true

# --- ANSI color codes ---
RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

# --- Usage ---
usage() {
    cat <<'EOF'
Usage: <input> | colorize.sh [OPTIONS]

Parse iptables/netfilter firewall log lines into fixed-width, color-coded
column output with GeoIP country lookups.

Options:
  -u, --show-unmatched  Print non-matching lines as-is (default: skip)
  -n, --no-color        Disable ANSI color codes
  -h, --help            Show this help message

Examples:
  cat /var/log/syslog | colorize.sh
  tail -f /var/log/syslog | colorize.sh -u
  grep 'policy' /var/log/syslog | colorize.sh --no-color > out.log
EOF
    exit 0
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--show-unmatched)
            SHOW_UNMATCHED=true
            shift
            ;;
        -n|--no-color)
            USE_COLOR=false
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Try 'colorize.sh --help' for usage information." >&2
            exit 1
            ;;
    esac
done

# Disable color if stdout is not a terminal (unless explicitly set)
if [[ "$USE_COLOR" == true ]] && [[ ! -t 1 ]]; then
    USE_COLOR=false
fi

# --- Check for geoiplookup ---
if ! command -v geoiplookup &>/dev/null; then
    echo "Warning: geoiplookup not found. Install geoip-bin for country lookups." >&2
    echo "  sudo apt install geoip-bin" >&2
    HAS_GEOIP=false
else
    HAS_GEOIP=true
fi

# --- GeoIP lookup function ---
# Returns "CC CountryName" or "-- unknown"
geoip_lookup() {
    local ip="$1"

    if [[ "$HAS_GEOIP" == false ]]; then
        echo "-- unknown"
        return
    fi

    local result
    result=$(geoiplookup "$ip" 2>/dev/null) || true

    # geoiplookup output: "GeoIP Country Edition: CC, Country Name"
    # or "GeoIP Country Edition: IP Address not found"
    if [[ "$result" == *"IP Address not found"* ]] || [[ -z "$result" ]]; then
        echo "-- unknown"
    else
        local cc country
        # Extract "CC, Country Name" after the colon
        local tail="${result#*: }"
        cc="${tail%%,*}"
        country="${tail#*, }"
        echo "$cc $country"
    fi
}

# --- Classify log prefix -> action ---
# Returns PERMIT, DENIED, or empty string for no match
classify_action() {
    local line="$1"
    local lower="${line,,}"  # bash 4+ lowercase

    if [[ "$lower" == *"policy accepted"* ]]; then
        echo "PERMIT"
    elif [[ "$lower" == *"policy denied"* ]] || [[ "$lower" == *"iplist denied"* ]]; then
        echo "DENIED"
    else
        echo ""
    fi
}

# --- Extract a key=value field from the log line ---
extract_field() {
    local line="$1"
    local key="$2"

    if [[ "$line" =~ ${key}=([^ ]*) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo ""
    fi
}

# --- Extract the syslog timestamp (first 15 chars: "Mon DD HH:MM:SS") ---
extract_timestamp() {
    local line="$1"
    echo "${line:0:15}"
}

# --- Format and print a parsed log line ---
print_line() {
    local timestamp="$1"
    local action="$2"
    local iface="$3"
    local src_ip="$4"
    local src_port="$5"
    local dst_ip="$6"
    local dst_port="$7"
    local length="$8"
    local proto="$9"
    local geo_cc="${10}"
    local geo_country="${11}"

    local color=""
    local reset=""

    if [[ "$USE_COLOR" == true ]]; then
        if [[ "$action" == "PERMIT" ]]; then
            color="$GREEN"
            reset="$RESET"
        elif [[ "$action" == "DENIED" ]]; then
            color="$RED"
            reset="$RESET"
        fi
    fi

    # Fixed-width format:
    # Timestamp(15) Action(8) Iface(6) SrcIP(15) SrcPort(5) DstIP(15) DstPort(5) Len(5) Proto(4) CC(2) Country
    printf "%s ${color}%-6s${reset} %-6s %15s %5s %15s %5s %5s %-4s %-2s %s\n" \
        "$timestamp" \
        "$action" \
        "$iface" \
        "$src_ip" \
        "$src_port" \
        "$dst_ip" \
        "$dst_port" \
        "$length" \
        "$proto" \
        "$geo_cc" \
        "$geo_country"
}

# --- Main loop: read from stdin ---
while IFS= read -r line || [[ -n "$line" ]]; do
    # Classify the action
    action=$(classify_action "$line")

    # If no match, handle unmatched lines
    if [[ -z "$action" ]]; then
        if [[ "$SHOW_UNMATCHED" == true ]]; then
            echo "$line"
        fi
        continue
    fi

    # Extract fields
    timestamp=$(extract_timestamp "$line")
    iface=$(extract_field "$line" "IN")
    src_ip=$(extract_field "$line" "SRC")
    dst_ip=$(extract_field "$line" "DST")
    src_port=$(extract_field "$line" "SPT")
    dst_port=$(extract_field "$line" "DPT")
    length=$(extract_field "$line" "LEN")
    proto=$(extract_field "$line" "PROTO")

    # Default empty fields to dashes
    iface="${iface:--}"
    src_ip="${src_ip:--}"
    dst_ip="${dst_ip:--}"
    src_port="${src_port:--}"
    dst_port="${dst_port:--}"
    length="${length:--}"
    proto="${proto:--}"

    # GeoIP lookup on source IP
    geo_result=$(geoip_lookup "$src_ip")
    geo_cc="${geo_result%% *}"
    geo_country="${geo_result#* }"

    # Print formatted line
    print_line "$timestamp" "$action" "$iface" "$src_ip" "$src_port" \
        "$dst_ip" "$dst_port" "$length" "$proto" "$geo_cc" "$geo_country"
done
