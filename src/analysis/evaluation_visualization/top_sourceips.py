
import dpkt
import sys
import geoip2.database
import socket
import json
import pytz
import datetime
from geoip import open_database
import matplotlib.pyplot as plt
import matplotlib
TCP = dpkt.tcp.TCP


def main():
    scannedips = []
    f = open("country_uni.txt", "w")
    if len(sys.argv) > 2:
        return
    pcap_file = open(sys.argv[1], "rb")
    pcap = dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data
            src_ip = socket.inet_ntoa(ip_hdr.src)
            if src_ip not in scannedips:
                scannedips.append(src_ip)
                f.write(src_ip)
                f.write('\n')
        except Exception as e:
            print e
    print len(scannedips)
if __name__ == '__main__':
    main()
