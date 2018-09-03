# dns-spoofind

* Install scupy
`pip install scapy`
* Install netfilterqueue
`pip install netfilterqueue`
* Create queue
`iptables -I FORWARD -j NFQUEUE --queue-num 0`
* Run arp spoofing script
`python arp_spoofing.py -t target_ip -g gateway_ip`
* Run dns_spoofing script
`python dns_spoofing`

Run script with --help to get help
`python dns_spoofing.py --help`
