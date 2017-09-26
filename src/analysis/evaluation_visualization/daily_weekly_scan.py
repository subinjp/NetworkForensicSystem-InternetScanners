import json
import operator
from datetime import datetime
global ip_date,weekly_count,total_scans,daily_scans
ip_date = {}
fmt = '%Y-%m-%d'

def create_ip_date():
    #ip_date = {}
    with open('hor_result.txt') as f:
        data = json.load(f)
    for i,j in data.iteritems():
        for k,l in j.iteritems():
            for m,n in l.iteritems():
                if len(n) == 25:
                    ip,port,strdate = i.split('_')
                    date = datetime.strptime(strdate, fmt)
                    ip_port = ip+'_'+port
                    #print ip_port
                    if ip_port in ip_date:
                        ip_date[ip_port].append(date)
                    else:
                        ip_date[ip_port] = [date]
                         #sorted_dic = sorted(dictionary.items(), key=operator.itemgetter(1),reverse=True)
    daily_weekly()
def daily_weekly():
    f = open("daily_scans_ips.txt", "w")
    weekly_count = 0
    total_scans = 0
    daily_scans = 0
    for i,j in ip_date.iteritems():
        total_scans += 1
        if(len(j) == 2):
            #tstamp1 = datetime.strptime(j[1], fmt)
            #tstamp2 = datetime.strptime(j[0], fmt)
            tstamp1 = j[1]
            tstamp2 = j[0]
            if(tstamp2 - tstamp1).days == 7:
                weekly_count += 1
        if(len(j) == 3):
            tstamp2 = j[2]
            tstamp1 = j[1]
            tstamp0 = j[0]
            if(tstamp2 - tstamp1).days == 7 and (tstamp1 - tstamp0).days == 7:
                weekly_count += 1
        if(len(j) >=15):
            try:
                ip,port = i.split('_')
                lastindex = j.index(datetime.strptime('2017-03-30', fmt))
                firstindex = j.index(datetime.strptime('2017-03-16', fmt))
                if(lastindex - firstindex >= 14):
                    f.write("%s\n" % ip)
                    daily_scans += 1
            except Exception as e:
                pass
            #print 'dates', sorted(j)
    print 'daily scans',daily_scans
    print 'weekly scans',weekly_count
    print 'total scans',total_scans
    #print 'daily_scans%',(daily_scans/total_scans)*100
    #print 'weeklyscans%',weekly_count/total_scans


def main():
    create_ip_date()

if __name__ == '__main__':
    #global ip_date
    main()
    #print ip_date
