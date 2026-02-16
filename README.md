# colorize

A Bash script that parses iptables/netfilter firewall log lines and reformats them into easy-to-read, fixed-width column output with color highlighting and GeoIP country lookups.

## Example

Raw iptables log:
```
Feb 15 10:30:02 fw kernel: policy accepted IN=eth0 OUT= SRC=74.125.46.147 DST=199.101.96.49 LEN=42 PROTO=UDP SPT=57245 DPT=53
Feb 15 10:30:05 fw kernel: policy denied IN=eth0 OUT= SRC=192.168.1.100 DST=199.101.96.49 LEN=60 PROTO=TCP SPT=44821 DPT=8080
```

Colorized output:
```
Feb 15 10:30:02 PERMIT   eth0   74.125.46.147   57245 199.101.96.49      53    42 UDP FI Finland
Feb 15 10:30:05 DENIED   eth0   192.168.1.100   44821 199.101.96.49    8080    60 TCP -- unknown
```

PERMIT is displayed in green, DENIED in red.

## Requirements

- Bash 4+
- `geoiplookup` (from the `geoip-bin` package)

Install on Debian/Ubuntu:
```bash
sudo apt install geoip-bin geoip-database
```

## Installation

```bash
git clone <repo-url> && cd colorize
chmod +x colorize.sh
```

Optionally symlink into your PATH:
```bash
sudo ln -s "$(pwd)/colorize.sh" /usr/local/bin/colorize
```

## Usage

```bash
# Pipe log lines from a file
cat /var/log/syslog | ./colorize.sh

# Follow a live log
tail -f /var/log/syslog | ./colorize.sh

# Search and colorize
grep 'policy' /var/log/syslog | ./colorize.sh

# Include non-matching lines in output
cat /var/log/syslog | ./colorize.sh -u

# Disable color (for piping to a file)
cat /var/log/syslog | ./colorize.sh --no-color > filtered.log
```

## Options

| Flag | Description |
|------|-------------|
| `-u`, `--show-unmatched` | Print non-matching lines as-is (default: skip them) |
| `--no-color` | Disable ANSI color codes (useful for piping to files) |
| `-h`, `--help` | Show usage information |

## Log Prefix Classification

The script classifies iptables log lines based on their log prefix:

| Log Prefix | Action | Color |
|------------|--------|-------|
| `policy accepted` | PERMIT | Green |
| `policy denied` | DENIED | Red |
| `iplist denied` | DENIED | Red |

Lines that don't match any known prefix are skipped by default (use `-u` to show them).

## Output Columns

| Column | Description |
|--------|-------------|
| Timestamp | Original syslog timestamp (e.g., `Feb 15 10:30:02`) |
| Action | `PERMIT` or `DENIED` |
| Interface | Inbound interface (e.g., `eth0`) |
| Source IP | Source IP address |
| Source Port | Source port number |
| Dest IP | Destination IP address |
| Dest Port | Destination port number |
| Length | Packet length in bytes |
| Protocol | Protocol (TCP, UDP, ICMP, etc.) |
| Country Code | 2-letter ISO country code (`--` if unknown) |
| Country Name | Full country name (`unknown` if not found) |

## License

MIT
