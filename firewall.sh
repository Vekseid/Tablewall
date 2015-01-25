#!/bin/bash
#######################################################################
# This script was developed by Vekseid, MIT License 
# https://github.com/Vekseid/Tablewall
# Discussed at http://hexwiki.com/wiki/Iptables_(1.4)
#######################################################################
# This is a generic version of the script I use to protect my servers.
#
# This script has undergone several revisions. I was originally
# tarpitting telnet attempts to port 25, for example, thus TARPORTS.
# I no longer do this for several reasons, but haven't bothered with
# fully purging the code yet.
#######################################################################
# This script would not have been possible without Oskar Andreasson's
# IPTables Tutorial, found at:
# http://www.frozentux.net/iptables-tutorial/iptables-tutorial.html
# I additionally made use of a good amount of the information in Jan
# Engelhardt's "Detecting and deceiving network scans", found here:
# http://jengelh.medozas.de/documents/Chaostables.pdf
#######################################################################

#######################################################################
# Define variables to make for easy tuning.
# IPT - Location of the iptables binary
# SELFIPS      - The server's allocated IP addresses
# WHITELIST    - My own personal IPs, separated by spaces, CIDR style
#                for address blocks e.g. 127.0.0.0/8
# TRUSTEDFACES - Interfaces we trust, typically lo but could also have
#                e.g. eth1 in a two-server setup. Space separated
# BLACKLIST    - Hated IPs. Functions as whitelist.
# SSHIP        - IP address for SSH
# SAFEIPS      - Won't tarpit on this IP/mask
# SERVIPS      - Running SERVPORTS on this IP/mask
# SSHPORT      - The port I have SSH set to. This does not provide
#                much added security, but it makes logs less noisy.
#                I reccoment picking a number and using it for all of
#                your servers.
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
export IPT=/sbin/iptables
export SELFIPS="198.51.100.80/28 192.0.2.184/30 203.0.113.88"
export WHITELIST="203.0.113.32/28 203.0.113.45"
export TRUSTEDFACES="lo"
export BLACKLIST=""
export SSHIP="198.51.100.83"
export SSHPORT=23728
export SAFEIPS="198.51.100.82 198.51.100.187"
export SERVIPS="198.51.100.82"
export TARPORTS=25
export SERVPORTS="587,993"
export OPENPORTS="80,443,25565"
export UDPIPS=""
export UDPPORTS=""
export ALLOWPING=1
export USELOG=1

#######################################################################
# Ended up dropping this... IMO this is the responsibility of your
# host. Or if you are your own host, this is not done on your end
# machines.
#
# Retained solely to point out that people do this. However, keep in
# mind that each additional rule is more computing power for every
# connection.
#######################################################################
#export DROPLIST="/etc/iptables/spamhausdrop.dat"
#######################################################################

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
export CONNREPORT="-m connlimit --connlimit-above 256 --connlimit-mask 24"
export CONNLIMIT="-m connlimit --connlimit-above 512 --connlimit-mask 24"
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
# documentation. The man pages are not very helpful and the tutorial
# is extremely misleading on this match.
#
# Note that, this is from reading the source back in 2009. Things may
# have changed.
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
#   situations where srcip is used for the mask. Not only does this
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
# HASHPING   - Originally for pings, now for related/established ICMP
#              messages in general. To permit ICMP traceroutes, we're
#              fairly generous.
#######################################################################
export HASHPING="-m hashlimit --hashlimit-upto 5/second --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-srcmask 29 --hashlimit-name icmp --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 1000 --hashlimit-htable-expire 2000"
export HASHSSH="-m hashlimit --hashlimit-upto 3/minute --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 29 --hashlimit-name ssh --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 60000"
export HASHLOG="-m hashlimit --hashlimit-upto 2/minute --hashlimit-burst 240 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name log --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 120000"
export HASHCON="-m hashlimit --hashlimit-upto 2/minute --hashlimit-burst 240 --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-name con --hashlimit-htable-size 8192 --hashlimit-htable-max 8192 --hashlimit-htable-gcinterval 3000 --hashlimit-htable-expire 120000"
#######################################################################

#######################################################################
# Here we set some variables that are not 'user modified'.
#######################################################################
export DROPTARGET=DROP
# For awhile I logged all dropped packets, thus the following, but it's
# all noise and no signal. I prefer to log actual incidents.
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
# Interfaces we trust get a free pass. Don't even track, just accept.
#######################################################################

for i in $TRUSTEDFACES
do
  $IPT -t raw -A PREROUTING -i $i -j NOTRACK
  $IPT -A INPUT -i $i -j ACCEPT
done

#######################################################################
# Logging all dropped packets is 99.9% noise, but left in for debugging
# potential.
#######################################################################
#if [ $USELOG -eq 1 ] ; then
  #####################################################################
  # Log dropped packets. Only make the chain if logging is on.
  # This is only really useful to determine if you are under a serious
  # attack of some sort.
  #####################################################################
 # $IPT -N DRP
 # $IPT -A DRP $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: Dropped: "
 # $IPT -A DRP -j DROP
  #####################################################################
#fi

#######################################################################
# Accept from related connections, non-icmp established connections,
# related connections, and our chosen whitelist. Drop invalid sources
# and non-unicast packets/sources outright, as well as killing funny
# business.
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

# Iterate through Spamhaus DROP list, if we're using that.
#for i in $(cat $DROPLIST | grep -i SBL | cut -f  1 -d ';' )
#do
#  $IPT -A INPUT -s $i -j DROP
#done

# Iterate through our own ips - drop spoofed entries.
for i in $SELFIPS
do
  $IPT -A INPUT -s $i -j $DROPTARGET
done

#######################################################################
# I used to split out tcp traffic and rate limit that. It really only
# caught exceptionally bad ISPs with legitimate users and aggressive
# web spiders. Low-end DDOS attempts are best mitigated with connlimit
# and possibly checking for lots of very small packets.
#
# I've found that the INVALID state actually spends most of its time
# dropping legitimate traffic. I can't really recommend it. You can
# do just as well by being picky with what you accept for NEW
# connections.
#
# Somewhere along the line, pings make established connections now.
# Annoying, but only minor changes needed to segregate established
# ICMP traffic. For sure, permit related traffic.
#######################################################################
$IPT -A INPUT -m state --state RELATED -j ACCEPT
$IPT -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
$IPT -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
# Drop garbage sources and destinations.
$IPT -A INPUT -m pkttype ! --pkt-type unicast -j $DROPTARGET
$IPT -A INPUT -m addrtype ! --src-type UNICAST -j $DROPTARGET
$IPT -A INPUT -m addrtype --dst-type BROADCAST -j $DROPTARGET
#######################################################################

#######################################################################
# TCPMESS is our version of the CHAOS target.
# The primary purpose of this is not even to deceive, but simply to
# increase the cost of portscanning. This is more of a nuisance than
# actual security.
#######################################################################
$IPT -N TCPMESS
#$IPT -A TCPMESS -p tcp -m statistic --mode random --probability 0.03 -j DELUDE
$IPT -A TCPMESS -p tcp -m statistic --mode random --probability 0.0208 -j REJECT --reject-with tcp-reset
$IPT -A TCPMESS -p tcp -m statistic --mode random --probability 0.0211 -j REJECT --reject-with host-unreach
$IPT -A TCPMESS -j DROP
#######################################################################

#######################################################################
# New TCP Traffic going to valid ports gets sent here.
# Check connlimit, check new connection rates, log nonsense.
#######################################################################
$IPT -N TCPIN
$IPT -A TCPIN -m recent --update --seconds 900 --hitcount 1 --name flooders -j DROP
$IPT -A TCPIN -p tcp $CONNREPORT $HASHCON -j LOG $LOGCON --log-prefix "Hackers: Many Connections: "
$IPT -A TCPIN -p tcp $CONNREPORT $HASHCON -m state --state INVALID -j $DROPTARGET
$IPT -A TCPIN -p tcp $CONNLIMIT -m recent --set --name flooders
$IPT -A TCPIN -p tcp $CONNLIMIT -j LOG $LOGCON --log-prefix "Hackers: Connection Overlimit: "
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
  $IPT -A TCPIN $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: Invalid Connect: "
fi
$IPT -A TCPIN -j DROP
#######################################################################

#######################################################################
# TCP traffic for our standard ports are not hindered for the purposes
# of automated blocking of general hijinks.
#
# We accept things on open ports, except for our secret (in this case,
# our SSH port), and we shut people poking around for a few hours.
#
# $TARPORTS still gets used here to drop spammers, regardless.
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
$IPT -A INPUT -p tcp -d $SSHIP --dport $SSHPORT $HASHCON -j LOG $LOGCON --log-prefix "Hackers: SSH Flood: "
$IPT -A INPUT -p tcp -m recent --set --name scanners
$IPT -A INPUT -p tcp -d $SSHIP --dport $SSHPORT -j TCPMESS
if [ $USELOG -eq 1 ] ; then
  $IPT -A INPUT -p tcp $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: Scanner: "
fi
$IPT -A INPUT -p tcp -j TCPMESS
#######################################################################

#######################################################################
# Overall ICMP Rules
#######################################################################
if [ $ALLOWPING -eq 1 ] ; then
  #####################################################################
  # ICMP Incoming Chain. This looks like it's blocking more than it
  # actually is - a lot of incoming ICMP messages are RELATED.
  #####################################################################
  $IPT -N ICMP
  if [ $USELOG -eq 1 ] ; then
    $IPT -A ICMP -p icmp --fragment $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: ICMP Fragment: "
  fi
  $IPT -A ICMP -p icmp --fragment -j DROP
  $IPT -A ICMP -p icmp --icmp-type echo-request -j ACCEPT
  # These generally get through first via accepting RELATED
  # connections, this is simply to be certain.
  $IPT -A ICMP -p icmp --icmp-type 3 -j ACCEPT
  $IPT -A ICMP -p icmp --icmp-type 4 -j ACCEPT
  if [ $USELOG -eq 1 ] ; then
    $IPT -A ICMP -p icmp $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: ICMP Bad: "
  fi
  #####################################################################

  #####################################################################
  # Allow icmp packets at the rate given in HASHPING.
  # You tend not to see ping floods these days, but it may be
  # interesting enough to log.
  #####################################################################
  $IPT -A INPUT -p icmp -m state --state NEW,ESTABLISHED $HASHPING -j ICMP
  if [ $USELOG -eq 1 ] ; then
    $IPT -A INPUT -p icmp -m state --state NEW,ESTABLISHED $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: ICMP Flood: "
  fi
  $IPT -A INPUT -p icmp -j DROP
  #####################################################################
fi
#######################################################################

#######################################################################
# UDP Rules.
#
# This messes with scanners.
#
# Probability in the .03-.04 range is apparently ideal.
# If you are more concerned about confusing scans of your network as
# opposed to scans of a single IP, using proto-unreach liberally can
# confuse protocol scans.
#
# Note, this blocks standard traceroutes. ICMP traceroutes work,
# however, which Windows falls back on and *nix can use via the -I 
# switch.
#######################################################################
$IPT -N UDPFUN
# Logging this is mostly noise.
#if [ $USELOG -eq 1 ] ; then
#  $IPT -A UDPFUN $HASHLOG -j LOG $LOGLEVEL --log-prefix "IPTables: UDP: "
#fi
$IPT -A UDPFUN -m statistic --mode random --probability 0.02 -j REJECT --reject-with proto-unreach
$IPT -A UDPFUN -m statistic --mode random --probability 0.0202 -j REJECT --reject-with host-unreach
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
