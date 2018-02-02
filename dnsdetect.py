import argparse
from scapy.all import *
import sys
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.inet import IP


def get_arguments():
    parser = argparse.ArgumentParser(add_help=False,
                                     description="DNSdetect to detect spoofed responses")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--interface", default="ens33")
    group.add_argument("-r", "--rfile")
    parser.add_argument('expression', nargs='*')
    parser.add_argument('-help', '--help', action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.help:
        parser.print_help()
        sys.exit()
    return args.interface, args.rfile, args.expression


def print_result(pkt, packet):
    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y%m%d-%H:%M:%S.%f')
    print(timestamp + " DNS poisoning attempt")
    print("TXID 0x%x Request %s" % (pkt[DNS].id, pkt[DNS].qd.qname.rstrip('.')))
    answer1 = []
    answer2 = []
    for x in range(pkt[DNS].ancount):
        pattern = r'[0-9]+(?:\.[0-9]+){3}'
        match = re.search(pattern, pkt[DNSRR][x].rdata)
        if match:
            answer1.append(pkt[DNSRR][x].rdata)
    for x in range(packet[DNS].ancount):
        pattern = r'[0-9]+(?:\.[0-9]+){3}'
        match = re.search(pattern, packet[DNSRR][x].rdata)
        if match:
            answer2.append(packet[DNSRR][x].rdata)
    print("Answer1 %s" % answer1)
    print("Answer2 %s" % answer2)


packets_sniffed = set()


def check_reverse_lookup(pkt, packet):
    host1=""
    host2=""
    for x in range(pkt[DNS].ancount):
        pattern = r'[0-9]+(?:\.[0-9]+){3}'
        match = re.search(pattern, pkt[DNSRR][x].rdata)
        if match:
            try:
                host1 = socket.gethostbyaddr(str(pkt[DNSRR][x].rdata))

            except socket.error:
                host1=""
            break
    for x in range(packet[DNS].ancount):
        pattern = r'[0-9]+(?:\.[0-9]+){3}'
        match = re.search(pattern, packet[DNSRR][x].rdata)
        if match:
            try:
                print(packet[DNSRR][x].rdata)
                host2 = socket.gethostbyaddr(str(packet[DNSRR][x].rdata))
            except socket.error:
                host2=""
            break
    if host1 is "" and host2 is "":
        return True
    elif host1 == host2:
        return False
    else:
        return True

def check_false_positive(pkt,packet):
     count1 = pkt[DNS].ancount
     count2 = packet[DNS].ancount
     for i in range(count1):
             print(pkt[DNSRR][i].rdata)
             if pkt[DNSRR][i].rdata in packet[DNSRR].rdata:
                print(pkt[DNSRR][i].rdata)
                return False
     return True



def dns_detect(packet):
    if packet.haslayer(DNSRR):
        if len(packets_sniffed) > 0:
            for pkt in packets_sniffed:
                if pkt[DNS].id == packet[DNS].id and \
                                pkt[IP].sport == packet[IP].sport and \
                                pkt[IP].dport == packet[IP].dport and \
                                pkt[DNSRR].rdata != packet[DNSRR].rdata and \
                                pkt[IP].dst == packet[IP].dst and \
                                pkt[DNS].qd.qname == packet[DNS].qd.qname and \
                                pkt[IP].payload != packet[IP].payload:
                    #if check_reverse_lookup(pkt, packet):
                        #print_result(pkt, packet)
                        if check_false_positive(pkt, packet):
                            print_result(pkt, packet)
        packets_sniffed.add(packet)


if __name__ == '__main__':
    interface, filename, bpf = get_arguments()
    hostmap = {}
    print interface
    print filename
    bpf_expr = ''
    if bpf:
        for s in bpf:
            bpf_expr = bpf_expr + s + ' '
    print("DNS forged response detector started...")
    if filename is not None:
        print("Reading pcap file trace:" + filename)
        if bpf_expr is not None:
            print("Filter expression:" + bpf_expr)
        sniff(filter=bpf_expr, offline=filename, store=0, prn=dns_detect)
    else:
        print("sniffing on interface:" + interface)
        if bpf_expr is not None:
            print("Filter expression:" + bpf_expr)
        sniff(filter=bpf_expr, iface=interface, store=0, prn=dns_detect)
