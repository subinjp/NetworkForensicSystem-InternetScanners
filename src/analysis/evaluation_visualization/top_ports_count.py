import dpkt
import json
import sys, socket
from datetime import datetime
import pickle
global top10
top10 = {}
tcp_ports = []
multiple_scannedports = []
top10tcp_ports = {}

def top10ports(ip_hdr, ts, buf):
    udp = ip_hdr.data
    dst_port = udp.dport
    if dst_port in top10:
        top10[dst_port] += 1
    else:
        top10[dst_port] = 1


def tcpports(ip_hdr, ts, buf):
    tcp = ip_hdr.data
    dst_port = tcp.dport
    if dst_port in top10tcp_ports:
        top10tcp_ports[dst_port] += 1
    else:
        top10tcp_ports[dst_port] = 1
    if dst_port not in tcp_ports:
        tcp_ports.append(dst_port)
    else:
        if dst_port not in multiple_scannedports:
            multiple_scannedports.append(dst_port)



def main():
    if len(sys.argv) > 2:
        return
    pcap_file = open(sys.argv[1], "rb")
    pcap = dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data
            if isinstance(ip_hdr.data, dpkt.udp.UDP):
                top10ports(ip_hdr, ts, buf)
            elif isinstance(ip_hdr.data, dpkt.tcp.TCP):
                tcpports(ip_hdr, ts, buf)
            else:
                print 's'
    sorted_dic = sorted(top10tcp_ports.items(), key=lambda x:x[1], reverse=True)
    for port,count in sorted_dic[:20]:
        perc = (float(count)/795792)*100
        print port,count, str(perc)

    #print sorted(top10.items(), key=lambda x:x[1], reverse=True)
    print len(tcp_ports)
    print len(multiple_scannedports)
if __name__ == '__main__':
    main()
