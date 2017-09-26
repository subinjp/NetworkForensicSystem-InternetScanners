import json
import matplotlib.pyplot as plt
import operator
import csv
global horizontal,vertical
horizontal = {}
vertical = {}
hor_scanned_ips = []
ver_scanned_ips = []
ports_ver = []
def largescansvertical():
    vertical_scans =0
    with open('vertical.txt') as f:
        ver_dic = json.load(f)
    num_des_ports = {}
    for i , j in ver_dic.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                if(len(n))>1:
                    ports_ver.extend(n)
                    srcip,dst_ip = i.split('_')
                    if srcip in num_des_ports:
                        num_des_ports[srcip].append(len(n))
                    else:
                        num_des_ports[srcip] = [len(n)]
    for i,j in num_des_ports.iteritems():
            ver_scanned_ips.append(i)
            print i,j
    print 'duplicates',len(ports_ver)
    print 'unique', len(list(set(ports_ver)))
                #num_des_ports.append(len(n))
def vertical_scan():
    vertical_scans =0
    with open('vertical.txt') as f:
        ver_dic = json.load(f)
    num_des_ports = []

    for i , j in ver_dic.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                num_des_ports.append(len(n))
    for ips in num_des_ports:
        if vertical.has_key(ips):
            vertical[ips] += 1
        else:
            vertical[ips] = 1
    del vertical[1]
    print 'vertical',vertical
    x = []
    y = []
    for key,value in vertical.iteritems():
        x.append(key)
        y.append(value)
        vertical_scans += value
    print 'Total Vertical scans',vertical_scans
    fig = plt.figure()
    ax = fig.add_subplot(111)
    list = [0,1,3,10,17,18,29]
    for i in list:
        xy = zip(x,y)
        ax.annotate('(%s, %s)' % xy[i], (x[i], y[i]))
    plt.xlabel('Number of Destination Ports scanned')
    plt.ylabel('Scans')
    plt.title('Vertical Scanning')
    plt.plot(x,y)
    #plt.show()
    plt.savefig('vertical_scans.png')
def largescanshorizontal():
    hor_scans = 0
    multiple = 0
    block_scans = 0
    multiple_scans = 0
    multiple_scanned_ips = []
    with open('horizontal.txt') as f:
        hor_dic = json.load(f)
    num_des_ips = {}
    for i , j in hor_dic.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                src_ip, dstprt = i.split('_')
                if (len(n)) ==25:
                    if src_ip in num_des_ips:
                        num_des_ips[src_ip] += 1
                    else:
                        num_des_ips[src_ip] = 1
    for i,j in num_des_ips.iteritems():
        hor_scanned_ips.append(i)
        hor_scans += 1
        if j>1:
            multiple += 1
    	    multiple_scanned_ips.append(i)
    common = set(hor_scanned_ips).intersection(ver_scanned_ips)
    for i , j in hor_dic.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                src_ip, dstprt = i.split('_')
                if (len(n)) ==25:
                    if src_ip in common:
                        block_scans += 1
                    if src_ip in multiple_scanned_ips:
                        multiple_scans +=1
    print 'total block scans', block_scans
    print 'total multiple scans',multiple_scans
    print 'total ips scanned 25 destination IPs', hor_scans
    print 'IPs scanned multiple times', multiple
    #common = set(hor_scanned_ips).intersection(ver_scanned_ips)
    print common
    print 'block scans', len(common)

def horizontal_scan():
    hor_scans = 0
    with open('horizontal.txt') as f:
        hor_dic = json.load(f)
    num_des_ips = []
    for i , j in hor_dic.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                num_des_ips.append(len(n))
    #print num_des_ips
    x = []
    y = []
    for ips in num_des_ips:
        if horizontal.has_key(ips):
            horizontal[ips] += 1
        else:
            horizontal[ips] = 1
    del horizontal[1]
    for key,value in horizontal.iteritems():
        x.append(key)
        y.append(value)
    fig = plt.figure()
    ax = fig.add_subplot(111)
    list = [0,3,8,13,18,23]
    for i in range(len(x)):
        hor_scans += y[i]
        ax.annotate(y[i], (x[i], y[i]))
    print 'Total horizontal scans',hor_scans
    for i in range(0,24):
	print x[i],y[i]
    plt.xlabel('Number of Destination IPs scanned')
    plt.ylabel('Scans')
    plt.title('Horizontal Scanning')
    plt.plot(x,y)
    plt.show()
    #plt.savefig('horizontal_scans.png')

def scanned_ports():
    with open('scannedports.txt') as f:
        ports_dic = json.load(f)
    x = []
    list = []
    for i,j in ports_dic.iteritems():
        x.append(i)
        list.append(j)
    y = []
    for dic in list:
        for key,value in dic.iteritems():
            y.append(value)
    dictionary = dict(zip(x, y))
    sorted_dic = sorted(dictionary.items(), key=operator.itemgetter(1),reverse=True)
    myfile = open('top_ports.txt', 'wb')
    for i in sorted_dic[:20]:
        j = str(i[0])+','+str(i[1])
        myfile.write(j+'\n')
def main():
    #horizontal_scan()
    #vertical_scan()
    largescansvertical()
    #largescanshorizontal()
    #scanned_ports()
if __name__ == '__main__':
    main()
