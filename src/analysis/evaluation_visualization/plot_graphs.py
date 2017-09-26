import json
import matplotlib.pyplot as plt
import operator
import csv
global horizontal,vertical
horizontal = {}
vertical = {}

def vertical_scan():
    with open('./analysis_results/vertical.txt') as f:
        ver_dic = json.load(f)
    num_des_ports = []
    for i in ver_dic.iteritems():
        num_des_ports.append(len(i[1]))

    for ips in num_des_ports:
        if vertical.has_key(ips):
            vertical[ips] += 1
        else:
            vertical[ips] = 1
    x = []
    y = []
    for key,value in vertical.iteritems():
        x.append(key)
        y.append(value)

    fig = plt.figure()
    ax = fig.add_subplot(111)
    print x,y
    list = [1,2,8,10,13]
    for i in list:
        xy = zip(x,y)
        ax.annotate('(%s, %s)' % xy[i], (x[i], y[i]))
    plt.xlabel('Number of Destination Ports scanned')
    plt.ylabel('Scans')
    plt.title('Vertical Scanning')
    plt.plot(x[1:],y[1:])
    #plt.show()
    plt.savefig('vertical_scans.png')

def horizontal_scan():
    with open('./analysis_results/horizontal.txt') as f:
        hor_dic = json.load(f)
    num_des_ips = []
    for i in hor_dic.iteritems():
        num_des_ips.append(len(i[1]))

    for ips in num_des_ips:
        if horizontal.has_key(ips):
            horizontal[ips] += 1
        else:
            horizontal[ips] = 1
    x = []
    y = []
    for key,value in horizontal.iteritems():
        x.append(key)
        y.append(value)

    fig = plt.figure()
    ax = fig.add_subplot(111)
    list = [1,4,9,14,19,24]
    for i in list:
        ax.annotate(y[i], (x[i], y[i]))
    plt.xlabel('Number of Destination IPs scanned')
    plt.ylabel('Scans')
    plt.title('Horizontal Scanning')
    plt.plot(x[1:],y[1:])
    #plt.show()
    plt.savefig('horizontal_scans.png')

def scanned_ports():
    with open('./analysis_results/scannedports.txt') as f:
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
    horizontal_scan()
    vertical_scan()
    scanned_ports()
if __name__ == '__main__':
    main()