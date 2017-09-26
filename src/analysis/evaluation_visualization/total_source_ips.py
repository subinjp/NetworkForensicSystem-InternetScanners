




def main():
    if len(sys.argv) > 2:
        return
    pcap_file = open(sys.argv[1], "rb")
    pcap = dpkt.pcap.Reader(pcap_file)
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data
            extract_country(ip_hdr,ts)
        except Exception as e:
            print e
    f = open("country_uni.txt", "w")
    json.dump(country_ts, f)
    top5_countries()

if __name__ == '__main__':
    main()
