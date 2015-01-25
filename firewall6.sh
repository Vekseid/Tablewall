#!/bin/bash
#######################################################################
# This script was developed by Vekseid, MIT License
# https://github.com/Vekseid/Tablewall
# Discussed at http://hexwiki.com/wiki/Iptables_(1.4)
#######################################################################
# This is the IPv6 version of the main IPv4 Script.
# Much Copypasta, with a few exceptions, the main one being permitting
# all ICMPv6 traffic. It is more important, and less broken, in IPv6.
#######################################################################

#######################################################################
# Define variables to make for easy tuning.
# IPT - Location of the iptables binary
# SELFIPS      - The server's allocated IP addresses (Elliquiy's, here)
# WHITELIST    - My own personal IPs, separated by spaces, CIDR style
#                for address blocks e.g. 127.0.0.0/8
# TRUSTEDFACES - Interfaces we trust, typically lo but could also have
#                e.g. eth1 in a two-server setup. Space separated
# BLACKLIST    - Hated IPs. Functions as whitelist.
# SSHIP        - IP address for SSH
# SAFEIPS      - Won't tarpit on this IP/mask
# SERVIPS      - Running SERVPORTS on this IP/mask
# SSHPORT      - The port I have SSH set to.
# TARPORTS     - Ports we are going to tarpit when they get hit
#                improperly. Default to 25 (SMTP) to trap spambots.
# SERVPORTS    - Ports only open on the service IP
# OPENPORTS    - Chosen ports to open on all IPs.
# UDPIPS       - Space-separated list of IP addresses/masks to permit
#                UDP on.
# UDPPORTS     - Comma-separated list of ports to allow UDP.
# ALLOWPING    - Whether or not to allow public pings. I often have to
#                diagnose problems for my members so sure, why not : )
# USELOG       - Whether to use the basic log. Nothing in these logs
#                are fully reliable so I want to make them easy to
#                disable.
#######################################################################
export IPT=/sbin/ip6tables
export SELFIPS="2604:4500:0:7::/64 2604:4500::e02 2604:4500::e03"
export WHITELIST="2607:f128:4a:2::/64"
export TRUSTEDFACES="lo"
export BLACKLIST=""
export SSHIP="2604:4500:0:7:e::9"
export SSHPORT=23728
export SAFEIPS="2604:4500:0:7:3::2 2604:4500:0:7:1::7"
export SERVIPS="2604:4500:0:7:3::2"
export TARPORTS=25
export SERVPORTS="587,993"
export OPENPORTS="80,443,25565"
export UDPIPS=""
export UDPPORTS=""
export ALLOWPING=1
export USELOG=1

#######################################################################
# The following are 'more advanced' variables.
#
# CONNREPORT   - While the limit is initially far higher, we want to
#                be reporting far before then, to see how many
#                legitimate users a blanket cutoff may restrict in
#                the event of an attack.
# CONNLIMIT    - The connlimit match declaration - it declares how
#                many tcp connections may exist for a given IP block.
# LOGLEVEL     - Logging line for basic logging.
# LOGCON       - Logs more serious incidents - connection flooding and
#                so on, that we want more reliable data for.
#######################################################################
export CONNREPORT="-m connlimit --connlimit-above 256 --connlimit-mask 56"
export CONNLIMIT="-m connlimit --connlimit-above 512 --connlimit-mask 56"
export LOGLEVEL="--log-level debug --log-ip-options"
export LOGCON="--log-level debug --log-ip-options --log-tcp-sequence --log-tcp-options"
#######################################################################

#######################################################################
# The documentation on hashlimit could certainly use refinement. Worse,
# many examples might trick someone into using limit where a well-tuned
# hashlimit is really what they want - if they really want to take the
# performance hit at all.
#
# The following comes from reading the kernel module source, not the
# documentation : ) The man pages are not very helpful and the tutorial
# is extremely misleading on this match.
#
# --hashlimit-htable-gcinterval is always set to three seconds in these
#   examples, except for ping, but you may wish to slow this down if
#   you find your system cpu usage getting high under heavy loads.
#   Your load is going to be based loosely off of htable-size divided
#   by gcinterval. The default is 1000 (one second).
# --hashlimit-htable-expire is an easy one to calculate - just pick the
#   time when the hashlimit-upto/above will fill up your bucket, maybe
#   add a bit extra, or less if you don't care about occasional
#   overages. The default is 10000 (ten seconds).
# --hashlimit-htable-max to quote the current kernel source:
#   /* FIXME: do something. question is what.. */
#   It currently fires a kernel warning if the hash table is allowed
#   to grow beyond this size. It defaults to 8 times the htable-size,
#   and has a floor of htable-size if set to a low value.
#   There's no actual limit, however. I'm not convinced that the
#   hashlimit algorithm is all it could be >_>
#   I set this to htable-size since if somehow eight thousand
#   connections are open I rather want to be warned about it.
# --hashlimit-htable-size is the size of the hash index. A hash of
#   log(htable-size) is computed for whatever was given in mode/mask.
#   If two objects end up with the same hash, they get placed in a
#   chain which is iteratively searched.
#   DO NOT SET THIS LOW EXPECTING IT WILL THROTTLE A DDOS. In theory,
#   that is what htable-max is for. But only in theory.
#   It has a bit of a messy default:
#   num_physpages * page_size / 16384, with a cap of 8192 and a minimum
#   of 16. Pretty much anyone with 256mb+ of RAM is going to reach the
#   cap.
#   In addition to the basic memory for the table itself, you will
#   allocate pointer_bytes * 2 * htable-size in bytes for the table.
#   More memory gets allocated in other functions and I haven't fully
#   gone through the source, but for an amd64 machine that means 16
#   bytes per bucket.
#   Since this is the size of the full index and I have RAM to spare, I
#   set all of the tables to 8k. The main thing to worry about here is
#   the garbage collection interval, since this means it's checking
#   eight thousand -linked lists- every interval.
# --hashlimit-srcmask is probably best set to /29 for IPv4 in most
#   situations where srcip is used for the tuple. Not only does this
#   help reduce collision rates, /29's are often the same family or
#   local organization. It works fine to treat them in this manner.
#   The default for this and dstmask is 32 for IPv4 and 128 for IPv6.
#   If using IPv6, if you do not set this to at least as low as /64 you
#   are insane.
# --hashlimit-mode is a fairly straightforward setting. I would suggest
#   using separate hashes for different ports and destination ips for
#   most scenarios.
# --hashlimit-burst defaults to five. This determines the maximum size
#   of the bucket which gets filled by upto/above.
#
# HASHLOG    - The hashlimit declaration for basic logging. It's rather
#              heavily limited in order to keep us from flooding.
# HASHCON    - Log mass connection attempts
# HASHSSH    - Not needed with this current setup, it exists more to
#              limit getting my auth log slammed than anything.
# HASHICMP   - Accept all but the most crazy degrees of icmp madness.
#              commented out as it is currently unused.
#######################################################################
#export HASHICMP="-m hashlimit --hashlimit-upto 60/second --hashlimit-burst 240 --hashlimit-mode srcip --hashlimit-srcmask 56 --hashlimit-name icmp --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 1000 --hashlimit-htable-expire 2000"
export HASHSSH="-m hashlimit --hashlimit-upto 3/minute --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-name ssh --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 60000"
export HASHLOG="-m hashlimit --hashlimit-upto 2/minute --hashlimit-burst 240 --hashlimit-mode srcip --hashlimit-srcmask 56 --hashlimit-name log --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 120000"
export HASHCON="-m hashlimit --hashlimit-upto 2/minute --hashlimit-burst 240 --hashlimit-mode srcip --hashlimit-srcmask 56 --hashlimit-name con --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 120000"
#######################################################################

#######################################################################
# Here we set some variables that are not 'user modified'.
#######################################################################
export DROPTARGET=DROP
#if [ $USELOG -eq 1 ] ; then
#  export DROPTARGET=DRP
#fi
#######################################################################

#######################################################################
# Flush current rules and reset policies.
#######################################################################
$IPT -F
$IPT -X
$IPT -t raw -F
$IPT -t raw -X
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT
#######################################################################

#######################################################################
# Give the system some time to rest. Can be important if it's been
# tracking a lot.
#######################################################################
sleep 3

#######################################################################
# Don't track our interfaces we trust.
#######################################################################
for i in $TRUSTEDFACES
do
  $IPT -t raw -A PREROUTING -i $i -j NOTRACK
  $IPT -A INPUT -i $i -j ACCEPT
done

#if [ $USELOG -eq 1 ] ; then
  #####################################################################
  # Log dropped packets. Only make the chain if logging is on.
  # This is only really useful to determine if you are under a serious
  # attack of some sort.
  #####################################################################
#  $IPT -N DRP
#  $IPT -A DRP $HASHLOG -j LOG $LOGLEVEL --log-prefix "IP6Tables: Dropped: "
#  $IPT -A DRP -j DROP
  #####################################################################
#fi

#######################################################################
# Accept from established/related connections and our whitelist.
# Drop invalid sources and non-unicast # packets/sources outright, as
# well as killing funny business.
#######################################################################
# Iterate through whitelist entries
for i in $WHITELIST
do
  $IPT -A INPUT -p tcp -s $i -j ACCEPT
done

# Iterate through blacklist entries
for i in $BLACKLIST
do
  $IPT -A INPUT -s $i -j $DROPTARGET
done

# Iterate through our own ips - drop spoofed entries.
for i in $SELFIPS
do
  $IPT -A INPUT -s $i -j $DROPTARGET
done

# ICMP gets a pass in IPv6
$IPT -A INPUT -p ipv6-icmp -j ACCEPT

#######################################################################
# I used to split out tcp traffic and rate limit that. It really only
# caught exceptionally bad ISPs with legitimate users and aggressive
# web spiders. DDOS attempts are best mitigated with connlimit and
# possibly checking for lots of very small packets.
#
# I've found that the INVALID state actually spends most of its time
# dropping legitimate traffic. I can't really recommend it. You can
# do just as well by being picky with what you accept for NEW
# connections.
#######################################################################
$IPT -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Drop garbage sources and destinations.
$IPT -A INPUT -m pkttype ! --pkt-type unicast -j $DROPTARGET
$IPT -A INPUT -m addrtype ! --src-type UNICAST -j $DROPTARGET
#######################################################################

#######################################################################
# TCPMESS is our version of the CHAOS target.
# The primary purpose of this is not even to deceive, but simply to
# increase the cost of portscanning. It has a secondary purpose of
# obscuring potentially sensitive ports, like SSH.
#######################################################################
$IPT -N TCPMESS
#$IPT -A TCPMESS -p tcp -m statistic --mode random --probability 0.03 -j DELUDE
$IPT -A TCPMESS -p tcp -m statistic --mode random --probability 0.04 -j REJECT
$IPT -A TCPMESS -j DROP
#######################################################################

#######################################################################
# New TCP Traffic going to valid ports gets sent here.
# Check connlimit, check new connection rates, log nonsense.
#######################################################################
$IPT -N TCPIN
$IPT -A TCPIN -m recent --update --seconds 900 --hitcount 1 --name flooders -j DROP
$IPT -A TCPIN -p tcp $CONNREPORT $HASHCON -j LOG $LOGCON --log-prefix "Hackers6: Many Connections: "
$IPT -A TCPIN -p tcp $CONNREPORT $HASHCON -m state --state INVALID -j $DROPTARGET
$IPT -A TCPIN -p tcp $CONNLIMIT -m recent --set --name flooders
$IPT -A TCPIN -p tcp $CONNLIMIT -j LOG $LOGCON --log-prefix "Hackers6: Connection Overlimit: "
$IPT -A TCPIN -p tcp $CONNLIMIT -j REJECT --reject-with tcp-reset
$IPT -A TCPIN -p tcp --tcp-flags SYN,FIN,RST,PSH,URG SYN -j ACCEPT
#######################################################################
# Sometimes we see new connections from legitimate peoples that
# somehow escaped proper connection tracking. These are most
# frequently ACK, followed by RST, followed distantly by ACK PSH.
#######################################################################
$IPT -A TCPIN -p tcp --tcp-flags SYN,ACK,RST,URG ACK -j ACCEPT
$IPT -A TCPIN -p tcp --tcp-flags SYN,FIN,RST,PSH,URG RST -j ACCEPT
if [ $USELOG -eq 1 ] ; then
  $IPT -A TCPIN $HASHLOG -j LOG $LOGLEVEL --log-prefix "IP6Tables: Invalid Connect: "
fi
$IPT -A TCPIN -j DROP
#######################################################################

#######################################################################
# TCP traffic for our standard ports are not hindered for the purposes
# of automated blocking of general hijinks.
#
# Spammers trying to access port 25 on IPs I'm only using for hosting
# get tarpitted. Otherwise, we accept things on open ports, except for
# our secret (in this case, our SSH port), and we shut people poking
# around for a few hours.
#######################################################################
$IPT -A INPUT -p tcp -m multiport --dports $OPENPORTS -j TCPIN
for i in $SERVIPS
do
  $IPT -A INPUT -p tcp -d $i -m multiport --dports $SERVPORTS -j TCPIN
done
#$IPT -A INPUT -p tcp ! -d $SAFEIP -m multiport --dports $TARPORTS -j TARPIT
for i in $SAFEIPS
do
  $IPT -A INPUT -p tcp -d $i -m multiport --dports $TARPORTS -j TCPIN
done
$IPT -A INPUT -p tcp -m multiport --dports $TARPORTS -j DROP

$IPT -A INPUT -p tcp -m recent --update --seconds 3600 --hitcount 1 --name scanners -j TCPMESS
$IPT -A INPUT -p tcp -d $SSHIP --dport $SSHPORT $HASHSSH -j ACCEPT
$IPT -A INPUT -p tcp -d $SSHIP --dport $SSHPORT $HASHCON -j LOG $LOGCON --log-prefix "Hackers6: SSH Flood: "
$IPT -A INPUT -p tcp -m recent --set --name scanners
$IPT -A INPUT -p tcp -d $SSHIP --dport $SSHPORT -j TCPMESS
if [ $USELOG -eq 1 ] ; then
  $IPT -A INPUT -p tcp $HASHLOG -j LOG $LOGLEVEL --log-prefix "IP6Tables: Scanner: "
fi
$IPT -A INPUT -p tcp -j TCPMESS
#######################################################################

#######################################################################
# Overall ICMP Rules
# 
# This is all commented out. I've not found a good use case for
# blocking any v6 ICMP packets yet. It is a much more 'modern'
# protocol.
#######################################################################
#$IPT -A INPUT -p ipv6-icmp -m state --state NEW $HASHICMP -j ACCEPT
#if [ $USELOG -eq 1 ] ; then
#  $IPT -A INPUT -p ipv6-icmp -m state --state NEW $HASHLOG -j LOG $LOGLEVEL --log-prefix "IP6Tables: ICMP Flood: "
#fi
#$IPT -A INPUT -p ipv6-icmp -j DROP
#######################################################################

#######################################################################
# UDP Rules.
#
# Mess with scanners.
# Probability in the .03-.04 range is apparently ideal.
# If you are more concerned about confusing scans of your network as
# opposed to scans of a single IP, using proto-unreach liberally can
# confuse protocol scans.
#######################################################################
$IPT -N UDPFUN
# Recording UDP scans is largely wasted space.
#if [ $USELOG -eq 1 ] ; then
#  $IPT -A UDPFUN $HASHLOG -j LOG $LOGLEVEL --log-prefix "IP6Tables: UDP: "
#fi
$IPT -A UDPFUN -m statistic --mode random --probability 0.04 -j REJECT
$IPT -A UDPFUN -j DROP
#######################################################################
# UDP rules -must- come after dropping spoofed addresses.
#######################################################################
for i in $UDPIPS
do
  $IPT -A INPUT -p udp -d $i -m multiport --dports $UDPPORTS -j ACCEPT
done
$IPT -A INPUT -p udp -j UDPFUN
#######################################################################
