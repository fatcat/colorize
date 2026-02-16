#!/bin/bash
# This script is meant to be deployed on a host that has a direct connection
# to the internet, but you don't want to let it be wide-open to the whole world. 
# You can set a "home" IP below, and then specific services you permit will be 
# allowed to the host. All other traffic will be denied.

if [ $UID != "0" ]; then
  echo "Must be run as root user"
  exit 1
fi

# Replace x.x.x.x with the ip from which you want to accept privileged traffic
HOME_IP="x.x.x.x"

# This script uses "at" to provide simple way of reverting a botched rule set.
# There is little worse than cutting off your access to a remote host, and this
# is an attempt to provide a means to prevent that.

# Upon running the script, an "at" job is setup that will flush the newly deployed
# rules, but in those 2 minutes you should test the new rules. If the new rules
# do cut off your access, you will not be able to cancel the at job. The bad 
# rules will be flushed, allowing you to reconnect to the host and fix the rules.

# If the rules work, then use "atrm <job id>" to remove at at job. If the rules
# don't work and you lose access, after two minutes iptables will be flushed and
# the system will become accessible, but it will have no rules in place.

# "norollback" is an optional argument that prevents the at job from being set
# up. Use this only after thoroughly testing the rules.

if [ "$1" == "norollback" ] ; then
  echo "Skipping \"at\" job for auto-rollback"
else
  atjobid=`echo "iptables -X; iptables -F" | \
  at now + 2 minute 2>&1 | \
  grep -v '^warning' | cut -d " " -f 2`

  echo "If the new rules work, remove the \"at\" job using \"atq\" and"
  echo "\"atrm ${atjobid}\" or iptables will be flushed after 2 minutes"
  echo
fi

# Clear everything to prepare for the desired chains
iptables -F
iptables -X

# The following chains are required to differentiate permit from denied traffic
# and is used by rsyslog. See the README.
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

# Privileged traffic rules
# Services you want to permit from a specific IP, like your home
for ip in $HOME_IP ; do
  iptables -A INPUT -p tcp --dport 22 -s $ip -j LOGNACCEPT
  iptables -A INPUT -p tcp --dport 80 -s $ip -j LOGNACCEPT
  iptables -A INPUT -p tcp --dport 443 -s $ip -j LOGNACCEPT
done

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

# This is the last rule that gets processed. Anything that isn't expressly permitted
# before this line is dropped by this line.
iptables -A INPUT -j LOGNDROP