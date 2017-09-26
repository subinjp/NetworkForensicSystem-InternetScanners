#from __future__ import print_function
import collections
import dpkt
import json
import sys, socket
from datetime import datetime
import pickle
global recent_scans,pec_ports,udpscan_dic,halfscandic, fullscandic, srcip_addr, horizontal_scan, scanned_ports, vertical_scan, scanned_ips, threewayhandshake, fullscancheck,scanned_udpports,scanned_udpips

# global synscan_count,conctscan_count,finscan_count
# conctscan_count = 0
# finscan_count = 0

'''
halfscandic -- To store the packets  to check if its syn scan packet
horizontal_scan -- To store the horizontal scans
vertical_scan -- To store the vertical scans
scanned_ports -- To store the distinct scanned ports
scanned_ips -- To store the distinct scanned ip addresses

'''
time_format = '%Y-%m-%d %H:%M:%S'
date_format = '%Y-%m-%d'
spec_ports = [7,53,111,123,137,161,177,500,520,1645,2049,5353,10080]
udpscan_dic = {}
halfscandic = {}
fullscandic = []
fullscancheck = {}
threewaydic = []
horizontal_scan = {}
vertical_scan = {}
scanned_ports = {}
scanned_ips = []
scanned_udpports = []
scanned_udpips = []
threewayhandshake = []
recent_scans = collections.OrderedDict()

TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP

# The file to save the syn packets of scanned attempts
scan_file = open("scan_pckts.pcap", "wb")
writer = dpkt.pcap.Writer(scan_file)
scan_file1 = open("udpscan_pckts.pcap", "wb")
writerudp = dpkt.pcap.Writer(scan_file1)
fmt = '%Y-%m-%d %H:%M:%S'


'''To check whether the connection is attempting for threewayhandshake
    syn->syn/ack->ack
'''



def threewaycheck(ts, buf, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, syn_flag, ack_flag, rst_flag):
    global connectscan_count
    if syn_flag == 1 and ack_flag == 0:
        temp = srcip_dstip + "_" + str(seq_num)
        threewaydic.append(temp)

        '''elif syn_flag == 1 and ack_flag == 1:
        temp = dstip_srcip + "_" + str(seq_num)
        for i in threewaydic:
            if i == dstip_srcip + "_" + str(ack_num - 1):
                del threewaydic[threewaydic.index(i)]
                threewaydic.append(temp)'''
    elif ack_flag == 1 and rst_flag == 0:
        for i in threewaydic:
            if i == srcip_dstip + "_" + str(seq_num - 1):
                del threewaydic[threewaydic.index(i)]
                threewayhandshake.append(src_ip + ":" + str(src_port) + "->" + dst_ip + ":" + str(dst_port))

        '''check if the connection is trying for connect scan
            syn -> syn/ack -> ack/rst
        '''
    elif ack_flag == 1 and rst_flag == 1:
        for i in threewaydic:
            if i == srcip_dstip + "_" + str(ack_num - 1):
                del threewaydic[threewaydic.index(i)]
                fullscandic.append(src_ip + ":" + str(src_port) + "->" + dst_ip + ":" + str(dst_port))
                threewayhandshake.append(src_ip + ":" + str(src_port) + "->" + dst_ip + ":" + str(dst_port))
                writer.writepkt(buf, ts)
                connectscan_count += 1

                if scanned_ports.has_key(dst_port):
                    scanned_ports[dst_port] += 1
                else:
                    scanned_ports[dst_port] = 1

                if src_ip not in scanned_ips:
                    scanned_ips.append(src_ip)



'''To check the half connect scan which includes closed and open ports scan
    open port :   syn -> syn/ack -> rst
    closed port : syn -> rst/ack
'''


def halfconnect_scan(ts, buf, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, syn_flag, rst_flag, ack_flag):
    global synscan_count
    date_time = str(datetime.fromtimestamp(ts))
    date, timev = date_time.split()
    hr_min_sec, ms = timev.split(".")
    date_time = date+" "+hr_min_sec
    # To check for the first syn packet of the connection
    if syn_flag == 1 and ack_flag == 0:

        halfscandic[srcip_dstip + "_" + str(seq_num)] = {'time': ts, 'data': buf}

        ''' To check if the port is closed
            closed port : syn -> rst/ack
        '''
    elif rst_flag == 1 and ack_flag == 1:
        # extract only the network which is scanning the ips
        a, b, c, d = dst_ip.split(".")
        tempkey = dstip_srcip + ':'+ str(src_port)
        #Check Recent_scans buffer to remove the duplicate packets.
        if tempkey not in recent_scans:
            t1 = datetime.strptime(date_time, time_format)
            if recent_scans:
                for k,v in recent_scans.iteritems():
                    t2 = datetime.strptime(v, time_format)
                    if (t1 - t2).seconds <120:
                        break
                    else:
                        del recent_scans[k]
            recent_scans[tempkey]= date_time
            print 'first:', t2, '-->last:', date_time
        else:
            return
        # ip_ts --- distinct keys for vertical_scan and horizontal scan dictionaries
        hor_ip_ts = a + "."+ b +"." + c +'_'+str(src_port)
        ver_ip_ts = a + "."+ b +"." + c +'_'+src_ip
        #print ver_ip_ts
        if halfscandic.has_key(dstip_srcip + "_" + str(ack_num - 1)):
            time = halfscandic[dstip_srcip + "_" + str(ack_num - 1)]['time']
            data = halfscandic[dstip_srcip + "_" + str(ack_num - 1)]['data']
            writer.writepkt(data, time)
            synscan_count += 1
            del halfscandic[dstip_srcip + "_" + str(ack_num - 1)]

            # Dictionary to store the scanned ports and the number of times each port scanned
            if scanned_ports.has_key(src_port):
                scanned_ports[src_port] += 1
            else:
                scanned_ports[src_port] = 1

            # array to store the distinct ip addresses which scanned the network telescope
            if dst_ip not in scanned_ips:
                scanned_ips.append(dst_ip)
            # Dictionary to store the Source IP addresses and different ports it scanned
            if ver_ip_ts in vertical_scan:
                for i in vertical_scan[ver_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if str(src_port) not in vertical_scan[ver_ip_ts][old_time]['port'+old_time]:
                        vertical_scan[ver_ip_ts][old_time]['port'+old_time].append(str(src_port))
                else:
                    port = [str(src_port)]
                    vertical_scan[ver_ip_ts][date_time] = vertical_scan[ver_ip_ts].pop(old_time)
                    vertical_scan[ver_ip_ts][date_time]['port'+date_time] = port
            else:
                port = [str(src_port)]
                vertical_scan[ver_ip_ts] = {}
                vertical_scan[ver_ip_ts][date_time] = {}
                vertical_scan[ver_ip_ts][date_time] = {'port'+date_time: port}
                #vertical_scan[ver_ip_ts] = {'time': date_time, key: port}
            # Dictionary to store the Source IP addresses and different IP addresses it scanned
            if hor_ip_ts in horizontal_scan:
                for i in horizontal_scan[hor_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if src_ip not in horizontal_scan[hor_ip_ts][old_time]['ip'+old_time]:
                        horizontal_scan[hor_ip_ts][old_time]['ip'+old_time].append(src_ip)
                else:
                    ip = [src_ip]
                    horizontal_scan[hor_ip_ts][date_time] = horizontal_scan[hor_ip_ts].pop(old_time)
                    horizontal_scan[hor_ip_ts][date_time]['ip'+date_time] = ip
            else:
                ip = [src_ip]
                horizontal_scan[hor_ip_ts] = {}
                horizontal_scan[hor_ip_ts][date_time] = {}
                horizontal_scan[hor_ip_ts][date_time] = {'ip'+date_time: ip}
            return synscan_count

        ''' To check if the port is open
            open port :   syn -> syn/ack -> rst
        '''
    elif rst_flag == 1:

        a, b, c, d = src_ip.split(".")
        hor_ip_ts = a + "." + b + "." + c + '_' + str(dst_port)
        ver_ip_ts = a + "." + b + "." + c + '_' + dst_ip

        if halfscandic.has_key(srcip_dstip + "_" + str(seq_num - 1)):
            time = halfscandic[srcip_dstip + "_" + str(seq_num - 1)]['time']
            data = halfscandic[srcip_dstip + "_" + str(seq_num - 1)]['data']
            writer.writepkt(data, time)
            synscan_count += 1
            del halfscandic[srcip_dstip + "_" + str(seq_num - 1)]

            if scanned_ports.has_key(dst_port):
                scanned_ports[dst_port] += 1
            else:
                scanned_ports[dst_port] = 1

            if src_ip not in scanned_ips:
                scanned_ips.append(src_ip)

            if ver_ip_ts in vertical_scan:
                for i in vertical_scan[ver_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if str(dst_port) not in vertical_scan[ver_ip_ts][old_time]['port'+old_time]:
                        vertical_scan[ver_ip_ts][old_time]['port'+old_time].append(str(dst_port))
                else:
                    port = [str(dst_port)]
                    vertical_scan[ver_ip_ts][date_time] = vertical_scan[ver_ip_ts].pop(old_time)
                    vertical_scan[ver_ip_ts][date_time]['port'+date_time] = port
            else:
                port = [str(dst_port)]
                vertical_scan[ver_ip_ts] = {}
                vertical_scan[ver_ip_ts][date_time] = {}
                vertical_scan[ver_ip_ts][date_time] = {'port'+date_time: port}

            if hor_ip_ts in horizontal_scan:
                for i in horizontal_scan[hor_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if dst_ip not in horizontal_scan[hor_ip_ts][old_time]['ip'+old_time]:
                        horizontal_scan[hor_ip_ts][old_time]['ip'+old_time].append(dst_ip)
                else:
                    ip = [dst_ip]
                    horizontal_scan[hor_ip_ts][date_time] = horizontal_scan[hor_ip_ts].pop(old_time)
                    horizontal_scan[hor_ip_ts][date_time]['ip'+date_time] = ip
            else:
                ip = [dst_ip]
                horizontal_scan[hor_ip_ts] = {}
                horizontal_scan[hor_ip_ts][date_time] = {}
                horizontal_scan[hor_ip_ts][date_time] = {'ip'+date_time: ip}
            return synscan_count
    else:
        return 0


'''Check if the scan is Full connect scan
    syn -> syn/ack -> ack/rst
'''


def connect_scan(ts, buf, src_ip, dst_ip,dst_port, seq_num,ack_flag, rst_flag,syn_flag):
    global connectscan_count
    date_time = str(datetime.fromtimestamp(ts))
    date, timev = date_time.split()
    hr_min_sec, ms = timev.split(".")
    date_time = date + " " + hr_min_sec
    # To check for the first syn packet of the connection
    if syn_flag == 1 and ack_flag == 0:
        fullscancheck[srcip_dstip + "_" + str(seq_num)] = {'time': ts, 'data': buf}

    elif ack_flag == 1 and rst_flag == 1:

        a, b, c, d = src_ip.split(".")
        hor_ip_ts = a + "." + b + "." + c + '_' + str(dst_port)
        ver_ip_ts = a + "." + b + "." + c + '_' + dst_ip

        if fullscancheck.has_key(srcip_dstip+"_"+str(seq_num - 1)):
            writer.writepkt(buf,ts)
            connectscan_count += 1
            del fullscancheck[srcip_dstip + "_" + str(seq_num - 1)]

            if scanned_ports.has_key(dst_port):
                scanned_ports[dst_port] += 1
            else:
                scanned_ports[dst_port] = 1

            if src_ip not in scanned_ips:
                scanned_ips.append(src_ip)

            if ver_ip_ts in vertical_scan:
                for i in vertical_scan[ver_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if str(dst_port) not in vertical_scan[ver_ip_ts][date_time]['port'+old_time]:
                        vertical_scan[ver_ip_ts][date_time]['port'+old_time].append(str(dst_port))
                else:
                    port = [str(dst_port)]
                    vertical_scan[ver_ip_ts][date_time] = vertical_scan[ver_ip_ts].pop(old_time)
                    vertical_scan[ver_ip_ts][date_time]['port'+date_time] = port
            else:
                port = [str(dst_port)]
                vertical_scan[ver_ip_ts] = {}
                vertical_scan[ver_ip_ts][date_time] = {}
                vertical_scan[ver_ip_ts][date_time] = {'port'+date_time: port}

            if hor_ip_ts in horizontal_scan:
                for i in horizontal_scan[hor_ip_ts]:
                    old_time = i
                tstamp1 = datetime.strptime(old_time, fmt)
                tstamp2 = datetime.strptime(date_time, fmt)
                if (tstamp2 - tstamp1).seconds <= 300:
                    if dst_ip not in horizontal_scan[hor_ip_ts][date_time]['ip'+old_time]:
                        horizontal_scan[hor_ip_ts][date_time]['ip'+old_time].append(dst_ip)
                else:
                    ip = [dst_ip]
                    horizontal_scan[hor_ip_ts][date_time] = horizontal_scan[hor_ip_ts].pop(old_time)
                    horizontal_scan[hor_ip_ts][date_time]['ip'+date_time] = ip
            else:
                ip = [dst_ip]
                horizontal_scan[hor_ip_ts] = {}
                horizontal_scan[hor_ip_ts][date_time] = {}
                horizontal_scan[hor_ip_ts][date_time] = {'ip'+date_time: ip}
            return connectscan_count
    else:
        return 0


'''Check if the scan is FIN scan
    if port is open - fin_flag -> No Reply
    if port is closed - fin_flag -> rst_flag
'''


def finscan(ts, buf, src_port, src_ip, fin_flag, rst_flag, ack_flag):
    if tempdata not in threewayhandshake:
        if fin_flag == 1 and rst_flag == 0 and ack_flag == 0:

            writer.writepkt(buf, ts)

            # Dictionary to store the scanned ports and the number of times each port scanned
            if scanned_ports.has_key(src_port):
                scanned_ports[src_port] += 1
            else:
                scanned_ports[src_port] = 1

            # array to store the distinct ip addresses which scanned the network telescope
            if src_ip not in scanned_ips:
                scanned_ips.append(src_ip)
            return True
    return False


'''Check if the scan is NULL scan
    here it does not set any tcp flags
'''


def nullscan(ts, buf, tcp, src_port, src_ip, syn_flag, rst_flag, ack_flag, fin_flag):
    psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
    urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
    ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
    cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0
    if syn_flag == 0 and ack_flag == 0 and fin_flag == 0 and psh_flag == 0 and urg_flag == 0 and ece_flag == 0 and cwr_flag == 0 and rst_flag == 0:
        writer.writepkt(buf, ts)
        # Dictionary to store the scanned ports and the number of times each port scanned
        if scanned_ports.has_key(src_port):
            scanned_ports[src_port] += 1
        else:
            scanned_ports[src_port] = 1

        # array to store the distinct ip addresses which scanned the network telescope
        if src_ip not in scanned_ips:
            scanned_ips.append(src_ip)
        return True
    return False


'''Check if the scan is Xmas scan
    here fin_flag,psh_flag and urg_flag set
'''


def xmasscan(ts, buf, tcp, src_port, src_ip, fin_flag):
    psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
    urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0

    if fin_flag == 1 and psh_flag == 1 and urg_flag == 1:
        writer.writepkt(buf, ts)
        # Dictionary to store the scanned ports and the number of times each port scanned
        if scanned_ports.has_key(src_port):
            scanned_ports[src_port] += 1
        else:
            scanned_ports[src_port] = 1

        # array to store the distinct ip addresses which scanned the network telescope
        if src_ip not in scanned_ips:
            scanned_ips.append(src_ip)
        return True
    return False



'''
    To check if the connection attempts port scanning which includes

    halfconnect scan, fullconnectscan, FIN Scan , UDP scanning
'''


def portscan_check(ip_hdr, ts, buf):
    global srcip_dstip, dstip_srcip, synscan_count, tempdata, finscan_count, nullscan_count, connectscan_count
    if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip_hdr.data
        src_port = tcp.sport
        dst_port = tcp.dport
        seq_num = tcp.seq
        ack_num = tcp.ack

        syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
        ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0

        src_ip = socket.inet_ntoa(ip_hdr.src)
        dst_ip = socket.inet_ntoa(ip_hdr.dst)

        srcip_dstip = src_ip + "->" + dst_ip
        dstip_srcip = dst_ip + "->" + src_ip

        tempdata = src_ip + ":" + str(src_port) + "->" + dst_ip + ":" + str(dst_port)
        if (halfconnect_scan(ts, buf, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, syn_flag, rst_flag,ack_flag) >= 1):
            pass

        elif (connect_scan(ts, buf, src_ip, dst_ip, dst_port, seq_num, ack_flag, rst_flag, syn_flag) >= 1):
            pass

        '''if tempdata not in threewayhandshake:
            threewaycheck(ts, buf, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, syn_flag, ack_flag, rst_flag)

        elif (finscan(ts, buf, src_port, src_ip, fin_flag, rst_flag, ack_flag) == True):
            finscan_count += 1

        elif (nullscan(ts, buf, tcp, src_port, src_ip, syn_flag, rst_flag, ack_flag, fin_flag) == True):
            nullscan_count += 1

        elif (xmasscan(ts, buf, tcp, src_port, src_ip, fin_flag)):
            xmasscan_count += 1'''

    '''if ip_hdr.p == dpkt.ip.IP_PROTO_UDP:
        print 's'
        udpscan(ts,buf)== True'''

def udpscan_check(ip_hdr,ts,buf):
    src_ip = socket.inet_ntoa(ip_hdr.src)
    dst_ip = socket.inet_ntoa(ip_hdr.dst)
    date_time = str(datetime.fromtimestamp(ts))
    date, timev = date_time.split()
    hr_min_sec, ms = timev.split(".")
    date_time = date+" "+hr_min_sec
    if isinstance(ip_hdr.data, dpkt.udp.UDP):
        udp = ip_hdr.data
        src_port = udp.sport
        dst_port = udp.dport
        a, b, c, d = src_ip.split(".")
        hor_ip_ts = a + "." + b + "." + c + '_' + str(dst_port)
        ver_ip_ts = a + "." + b + "." + c + '_' + dst_ip
        temp = src_ip+"->" +dst_ip + ":" + str(dst_port)
        revtemp = dst_ip +"->" + src_ip + ":" +str(src_port)
        if temp in udpscan_dic:
                if udpscan_dic[temp]['closed'] != 0:
                    udpscan_dic[temp]['time'] = ts
                    udpscan_dic[temp]['datas'] = buf
                elif udpscan_dic[temp]['closed'] == 0:
                    if dst_port not in scanned_udpports:
                        scanned_udpports.append(dst_port)
                    if src_ip not in scanned_udpips:
                        scanned_udpips.append(src_ip)
                    writerudp.writepkt(buf,ts)
                    vertical_scan1(ver_ip_ts,date_time,dst_port)
                    horizontal_scan1(hor_ip_ts,date_time,dst_ip)
        elif revtemp in udpscan_dic:
            tempkey = dst_ip+"->" +src_ip + ":" + str(src_port)
            if not check_recent_scans(tempkey,date_time):
                return
            if udpscan_dic[revtemp]['closed'] == 0:
                udpscan_dic[temp]['closed'] = 3
            a, b, c, d = dst_ip.split(".")
            hor_ip_ts = a + "."+ b +"." + c +'_'+str(src_port)
            ver_ip_ts = a + "."+ b +"." + c +'_'+src_ip
            times = udpscan_dic[revtemp]['time']
            datas = udpscan_dic[revtemp]['data']
            if src_port not in scanned_udpports:
                scanned_udpports.append(src_port)
            if dst_ip not in scanned_udpips:
                scanned_udpips.append(dst_ip)
            writerudp.writepkt(datas,times)
            # Dictionary to store the Source IP addresses and different ports it scanned
            vertical_scan2(ver_ip_ts,date_time,src_port)
            # Dictionary to store the Source IP addresses and different IP addresses it scanned
            horizontal_scan2(hor_ip_ts,date_time,src_ip)
        else:
            udpscan_dic[temp] = {'time': ts, 'data': buf, 'iphdr':ip_hdr,'closed': 0}
            #if len(udp.data) <=50:
            #    udpscan_dic[temp] = {'time': ts, 'data': buf, 'iphdr':ip_hdr, 'repeat': 1, 'closed': 0}
            #elif dst_port in spec_ports:
            #    udpscan_dic[temp] = {'time': ts, 'data': buf, 'iphdr':ip_hdr, 'repeat': 1, 'closed': 0}
    elif isinstance(ip_hdr.data, dpkt.icmp.ICMP):
        icmp = ip_hdr.data
        code = icmp.code
        types = icmp.type
        a, b, c, d = src_ip.split(".")
        if code == 3 and types == 3:
                icmp1 = (icmp.data)
                ip = icmp1.data
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                temp = dst_ip+ "->" + src_ip + ":" + str(dst_port)
                if not check_recent_scans(temp,date_time):
                    return
                hor_ip_ts = a + "." + b + "." + c + '_' + str(dst_port)
                ver_ip_ts = a + "."+ b +"." + c +'_'+src_ip
                if temp in udpscan_dic:
                    times = udpscan_dic[temp]['time']
                    datas = udpscan_dic[temp]['data']
                    if udpscan_dic[temp]['closed'] == 0:
                        udpscan_dic[temp]['closed'] = 1
                    udp = udpscan_dic[temp]['iphdr'].data
                    udp_srcport = udp.sport
                    if dst_port not in scanned_udpports:
                            scanned_udpports.append(dst_port)
                    if src_ip not in scanned_udpips:
                            scanned_udpips.append(src_ip)
                    writerudp.writepkt(datas,times)
                    horizontal_scan2(hor_ip_ts,date_time,src_ip)
                    vertical_scan1(ver_ip_ts,date_time,dst_port)
def check_recent_scans(temp,date_time):
    t1 = datetime.strptime(date_time, time_format)
    if temp not in recent_scans:
        if recent_scans:
            for k,v in recent_scans.iteritems():
                t2 = datetime.strptime(v, time_format)
                if (t1 - t2).seconds <600:
                    break
                else:
                    del recent_scans[k]
        print 'not in recent_scans'
        recent_scans[temp]= date_time
        return 1
    else:
        if recent_scans:
            for k,v in recent_scans.iteritems():
                t2 = datetime.strptime(v, time_format)
                if (t1 - t2).seconds <600:
                    break
                else:
                    del recent_scans[k]
        print 'recent_scans'
        return 0
def horizontal_scan1(hor_ip_ts,date_time,dst_ip):
    if hor_ip_ts in horizontal_scan:
        for i in horizontal_scan[hor_ip_ts]:
            old_time = i
        tstamp1 = datetime.strptime(old_time, fmt)
        tstamp2 = datetime.strptime(date_time, fmt)
        if (tstamp2 - tstamp1).seconds <= 300:
            if dst_ip not in horizontal_scan[hor_ip_ts][old_time]['ip'+old_time]:
                horizontal_scan[hor_ip_ts][old_time]['ip'+old_time].append(dst_ip)
        else:
            ip = [dst_ip]
            horizontal_scan[hor_ip_ts][date_time] = horizontal_scan[hor_ip_ts].pop(old_time)
            horizontal_scan[hor_ip_ts][date_time]['ip'+date_time] = ip
    else:
        ip = [dst_ip]
        horizontal_scan[hor_ip_ts] = {}
        horizontal_scan[hor_ip_ts][date_time] = {}
        horizontal_scan[hor_ip_ts][date_time] = {'ip'+date_time: ip}

def horizontal_scan2(hor_ip_ts,date_time,src_ip):
    if hor_ip_ts in horizontal_scan:
        for i in horizontal_scan[hor_ip_ts]:
            old_time = i
        tstamp1 = datetime.strptime(old_time, fmt)
        tstamp2 = datetime.strptime(date_time, fmt)
        if (tstamp2 - tstamp1).seconds <= 300:
            if src_ip not in horizontal_scan[hor_ip_ts][old_time]['ip'+old_time]:
                horizontal_scan[hor_ip_ts][old_time]['ip'+old_time].append(src_ip)
        else:
            ip = [src_ip]
            horizontal_scan[hor_ip_ts][date_time] = horizontal_scan[hor_ip_ts].pop(old_time)
            horizontal_scan[hor_ip_ts][date_time]['ip'+date_time] = ip
    else:
        ip = [src_ip]
        horizontal_scan[hor_ip_ts] = {}
        horizontal_scan[hor_ip_ts][date_time] = {}
        horizontal_scan[hor_ip_ts][date_time] = {'ip'+date_time: ip}

def vertical_scan1(ver_ip_ts,date_time,dst_port):
    if ver_ip_ts in vertical_scan:
        for i in vertical_scan[ver_ip_ts]:
            old_time = i
        tstamp1 = datetime.strptime(old_time, fmt)
        tstamp2 = datetime.strptime(date_time, fmt)
        if (tstamp2 - tstamp1).seconds <= 300:
            if str(dst_port) not in vertical_scan[ver_ip_ts][old_time]['port'+old_time]:
                vertical_scan[ver_ip_ts][old_time]['port'+old_time].append(str(dst_port))
        else:
            port = [str(dst_port)]
            vertical_scan[ver_ip_ts][date_time] = vertical_scan[ver_ip_ts].pop(old_time)
            vertical_scan[ver_ip_ts][date_time]['port'+date_time] = port
    else:
        port = [str(dst_port)]
        vertical_scan[ver_ip_ts] = {}
        vertical_scan[ver_ip_ts][date_time] = {}
        vertical_scan[ver_ip_ts][date_time] = {'port'+date_time: port}

def vertical_scan2(ver_ip_ts,date_time,src_port):
    if ver_ip_ts in vertical_scan:
        for i in vertical_scan[ver_ip_ts]:
            old_time = i
        tstamp1 = datetime.strptime(old_time, fmt)
        tstamp2 = datetime.strptime(date_time, fmt)
        if (tstamp2 - tstamp1).seconds <= 300:
            if str(src_port) not in vertical_scan[ver_ip_ts][old_time]['port'+old_time]:
                vertical_scan[ver_ip_ts][old_time]['port'+old_time].append(str(src_port))
        else:
            port = [str(src_port)]
            vertical_scan[ver_ip_ts][date_time] = vertical_scan[ver_ip_ts].pop(old_time)
            vertical_scan[ver_ip_ts][date_time]['port'+date_time] = port
    else:
        port = [str(src_port)]
        vertical_scan[ver_ip_ts] = {}
        vertical_scan[ver_ip_ts][date_time] = {}
        vertical_scan[ver_ip_ts][date_time] = {'port'+date_time: port}

def main():
    if len(sys.argv) > 2:
        return
    pcap_file = open(sys.argv[1], "rb")
    pcap = dpkt.pcap.Reader(pcap_file)
    global synscan_count, connectscan_count, finscan_count, nullscan_count, xmasscan_count
    synscan_count = 0
    connectscan_count = 0
    finscan_count = 0
    nullscan_count = 0
    xmasscan_count = 0
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_hdr = eth.data
            if isinstance(ip_hdr.data, dpkt.udp.UDP) or isinstance(ip_hdr.data, dpkt.icmp.ICMP):
                udpscan_check(ip_hdr,ts,buf)
            #if isinstance(ip_hdr.data, dpkt.tcp.TCP) :
             #   portscan_check(ip_hdr, ts, buf)
            else:
                pass
        except Exception as e:
           print e
    f = open("horizontal.txt", "wb")
    f1 = open("vertical.txt", "wb")
    f2 = open("scannedports.txt","wb")
    f3 = open("scannedips.txt","w")
    f4 = open("scannedudpports.txt","w")
    f5 = open("scannedudpips.txt","w")
    #f4 = open("counts.txt","w")
    json.dump(horizontal_scan, f)
    json.dump(vertical_scan, f1)
    json.dump(scanned_ports,f2)
    pickle.dump(scanned_ips,f3)
    json.dump(scanned_udpports,f4)
    json.dump(scanned_udpips,f5)
    counts = "synscan:"+str(synscan_count)+"connectscan:"+str(connectscan_count)+"finscan:"+str(finscan_count)+"nullscan:"+str(nullscan_count)+"xmasscan:"+str(xmasscan_count)
    print counts
if __name__ == '__main__':
    main()
