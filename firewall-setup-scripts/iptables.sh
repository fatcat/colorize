#!/bin/bash

if [ $UID != "0" ]; then
        echo "Must be run as root user"
        exit 1
fi

BLOCK_53="60.26.66.220 60.26.66.250 172.253.2.0/24 172.217.43.147 143.215.172.85"
HOME_IP=""
JUNIPER_IP=""
GCP_IP=""
LONESTAR_IP="205.166.94.30 205.166.94.16"
LETSENCRYPT="34.219.64.153 34.212.223.204 34.209.232.166 66.133.109.36 52.15.254.228 18.197.227.110"
#CURRENT_HOME_IP=$(dig @localhost firecat.the-mcnultys.org | cut -f 4)
CURRENT_HOME_IP="73.137.239.99"
HOME_IP="${HOME_IP} ${CURRENT_HOME_IP}"

# Allow 2 minutes to test the new rules. If the "at" job isn't canceled within
# 2 minutes the iptables rules will be flushed. If the rules work, then use
# "atq" to find the "at" job, and "atrm <job id>" to remove it. If the rules
# don't work and you lose access, after two minutes iptables will be flushed
# and custom chains removed.
if [ "$1" == "norollback" ] ; then
        echo "Skipping \"at\" job for auto-rollback"
else
        atjobid=`echo "iptables -X; iptables -F" | \
  at now + 2 minute 2>&1 | \
  grep -v '^warning' | cut -d " " -f 2`

  echo "If the new rules work, remove the \"at\" job using \"atq\" and"
        echo "\"atrm ${atjobid}\" or iptables will be flushed after 2 minutes"
        echo
        echo "Also be sure to save the rules:"
        echo "  \"iptables-save  > /etc/iptables/rules.v4\""
        echo "  \"ip6tables-save > /etc/iptables/rules.v6\""
        echo
fi

iptables -F
iptables -X

# Create a "log and drop" chain
iptables -N LOGNDROP
iptables -A LOGNDROP -j LOG --log-prefix "policy denied: " --log-level info
iptables -A LOGNDROP -j DROP

iptables -N LLOGNDROP
iptables -A LLOGNDROP -j LOG --log-prefix "iplist denied: " --log-level info
iptables -A LLOGNDROP -j DROP

# Create a "log and accept" chain
iptables -N LOGNACCEPT
iptables -A LOGNACCEPT -j LOG --log-prefix "policy accepted: " --log-level info
iptables -A LOGNACCEPT -j ACCEPT

# Allow all to loopback - this is the first rule that processes traffic
# and then they go in order as shown
iptables -I INPUT 1 -i lo -j ACCEPT

# Allow established
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow from anywhere
#iptables -A INPUT -j LOG --log-level 4
#iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Home
for ip in $HOME_IP ; do
        iptables -A INPUT -p tcp --dport 20 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 21 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 22 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 53 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p udp --dport 53 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 80 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 443 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 8888 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p udp --dport 500 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p udp --dport 4500 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 22000 -s $ip -j LOGNACCEPT # Syncthing
        iptables -A INPUT -p udp --dport 22000 -s $ip -j LOGNACCEPT # Syncthing
        iptables -A INPUT -p tcp --dport 25972 -s $ip -j LOGNACCEPT # BTSync
        iptables -A INPUT -p udp --dport 61798 -s $ip -j LOGNACCEPT # BTSync
        iptables -A INPUT -p tcp --dport 64624 -s $ip -j LOGNACCEPT # BTSync
        iptables -A INPUT -p tcp --dport 64624 -s $ip -j LOGNACCEPT # BTSync
done


# sdf.lonestar.org
for ip in $LONESTAR_IP; do
        iptables -A INPUT -p tcp --dport 22 -s $ip -j LOGNACCEPT
done

# google cloud
for ip in $GCP_IP; do
        iptables -A INPUT -p tcp --dport 22 -s $ip -j LOGNACCEPT
done

# Juniper NAT
for ip in $JUNIPER_IP ; do
        iptables -A INPUT -p tcp --dport 22 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 8888 -s $ip -j LOGNACCEPT
        iptables -A INPUT -p tcp --dport 64624 -s $ip -j LOGNACCEPT # BTSync
        iptables -A INPUT -p udp --dport 64624 -s $ip -j LOGNACCEPT # BTSync
done

# DNS Blocks
for ip in $BLOCK_53 ; do
        iptables -A INPUT -p udp --dport 53 -s $ip -j LOGNDROP
done

# Block DNS "ANY" queries
iptables -A INPUT -p udp -m udp --dport 53 -m string --hex-string "|0000ff0001|" --algo bm --from 48 --to 65535 -m recent --set --name dnsanyquery --rsource
iptables -A INPUT -p udp -m udp --dport 53 -m string --hex-string "|0000ff0001|" --algo bm --from 48 --to 65535 -m recent --rcheck --seconds 60 --hitcount 4 --name dnsanyquery --rsource -j LOGNDROP

# Allow DNS queries not dropped above
#iptables -A INPUT -p udp --dport 53 -j LOGNACCEPT

# Block feed IPs
#iptables -A INPUT -m set --match-set blocklist src -j LLOGNDROP


# Block fragments and other oddities
iptables -A INPUT -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOGNDROP
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j LOGNDROP
iptables -A INPUT -f -m limit --limit 5/m --limit-burst 7 -j LOGNDROP
iptables -A INPUT -f -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j LOGNDROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOGNDROP


# Let's Encrypt
#for ip in $LETSENCRYPT ; do
#       iptables -A INPUT -p tcp --dport 80 -s $ip -j LOGNACCEPT
#done

#iptables -t nat -A POSTROUTING -s 10.0.0.0/22 -o eth0 -j MASQUERADE

# --- Docker support ---
# Restart Docker daemon so it recreates its iptables chains (DOCKER,
# DOCKER-USER, DOCKER-ISOLATION-STAGE-*) in both filter and nat tables.
# This must run AFTER our INPUT rules are in place but BEFORE we save.
# Docker only touches FORWARD and nat — it won't interfere with INPUT.
if systemctl is-active --quiet docker; then
  echo "Restarting Docker to recreate iptables chains..."
  systemctl restart docker
fi

# Allow external access to Docker-proxied services
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Skip Docker's DNAT for web ports so docker-proxy handles connections
# (kernel forwarding is blocked by the hosting provider)
# Insert at top of nat DOCKER chain — immune to Docker recreating rules
iptables -t nat -I DOCKER 1 -p tcp --dport 443 -j RETURN
iptables -t nat -I DOCKER 1 -p tcp --dport 80 -j RETURN

# This is the last rule that gets processed.
iptables -A INPUT -j LOGNDROP

#echo $HOME_IP
