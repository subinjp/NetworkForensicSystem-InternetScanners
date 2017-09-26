
import dpkt
import sys, socket
import struct

TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP

# The file to save the zmap packets
scan_file = open("zmap_pckts.pcap", "wb")
zmap = dpkt.pcap.Writer(scan_file)

#the file to save massscan packets
scan_file = open("massscan.pcap", "wb")
massscan = dpkt.pcap.Writer(scan_file)

def finger_printing(ip_hdr, ts, buf):
    global mass_scan,zmap_scan
    if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip_hdr.data
        dst_port = tcp.dport
        seq_num = tcp.seq
        dst_ip = struct.unpack("!L", ip_hdr.dst)[0]
        fingerprint = dst_ip ^ dst_port ^ seq_num
        #check whether the packet is massscan
        if ip_hdr.id == fingerprint:
            mass_scan += 1
            massscan.writepkt(buf,ts)
        elif ip_hdr.id == 54321:
            zmap_scan += 1
            zmap.writepkt(buf,ts)


def main():
    global mass_scan,zmap_scan
    mass_scan = 0
    zmap_scan = 0
    if len(sys.argv) > 2:
        return
    pcap_file = open(sys.argv[1], "rb")
    pcap = dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data
            if type(ip_hdr.data) in (TCP, UDP):
                finger_printing(ip_hdr, ts, buf)
            else:
                print 's'
        except Exception as e:
            pass
    print 'zmapa_count',zmap_scan
    print 'massscan_count',mass_scan

if __name__ == '__main__':
    main()
