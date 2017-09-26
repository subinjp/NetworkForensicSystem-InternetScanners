
import json
import matplotlib.pyplot as plt
import operator
import csv

def scanned_ports():
    total_hits= 0
    with open('scannedports.txt') as f:
        ports_dic = json.load(f)
    x = []
    list = []
    for i,j in ports_dic.iteritems():
	total_hits +=  int(i)
        x.append(i)
        #print x
        list.append(j)
        #print list
    sorted_dic = sorted(ports_dic.items(), key=operator.itemgetter(1),reverse=True)
    myfile = open('top_ports.txt', 'wb')
    for i in sorted_dic[:20]:
        j = str(i[0])+','+str(i[1])
        myfile.write(j+'\n')
    print 'total hits',total_hits
    '''y = []
    for dic in list:
        for key,value in dic.iteritems():
            y.append(value)
    dictionary = dict(zip(x, y))
    sorted_dic = sorted(dictionary.items(), key=operator.itemgetter(1),reverse=True)
    myfile = open('top_ports.txt', 'wb')
    for i in sorted_dic[:20]:
        j = str(i[0])+','+str(i[1])
        myfile.write(j+'\n')'''
def main():
    #horizontal_scan()
    #vertical_scan()
    scanned_ports()
if __name__ == '__main__':
    main()
