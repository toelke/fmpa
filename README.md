# fmpa
file monitor port access:  This tool watches a directory for files called 4<ipv4-address> or 6<ipv6-address> and will create iptables-rules according to these files.

It will add an ACCEPTing rule for every source-ip that is specified as a file. If the file is removed the rule is removed.

So creating the file "4192.0.2.158" is the same as doing "iptables -A INPUT -p udp --dport 34197 -s 192.0.2.158 -j ACCEPT" (using the example config with UDP port 34197). The same holds for 62001:DB8::158 which will create an ip6tables entry.

For obvious reasons this program needs to be run as root.
