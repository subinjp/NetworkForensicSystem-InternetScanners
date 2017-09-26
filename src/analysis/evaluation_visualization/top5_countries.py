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
import numpy as np
TCP = dpkt.tcp.TCP
reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
db = open_database('GeoLite2-City.mmdb')
global country_ts,top5,countries
country_ts = {}
top5 ={}
countries = {}
server_timezone = pytz.timezone("Europe/Berlin")
time_format = '%Y-%m-%d %H:%M:%S'
def extract_country(ip_hdr,ts):
    src_ip = socket.inet_ntoa(ip_hdr.src)
    country = db.lookup(src_ip).country
    date_time = datetime.datetime.fromtimestamp(ts)
    timezone_ip = db.lookup(src_ip).timezone
    new_timezone = pytz.timezone(timezone_ip)
    time_new_timezone = server_timezone.localize(date_time).astimezone(new_timezone)
    new_time= str(time_new_timezone.replace(tzinfo=None,microsecond = 0))
    if country_ts.has_key(country):
        country_ts[country].append(new_time)
    else:
        timestamp = [new_time]
        country_ts[country] = timestamp

def count(prevs_time,last_time,time):
    no =0
    if last_time > time[-1]:
        last_time=time[-1]
    for i in time:
        if i>prevs_time and i<last_time:
            no +=1
    return no


def plot_graph(top5):
    plt.gca().set_color_cycle(['red', 'green', 'blue', 'yellow','violet'])
    country_code = []
    for country,a in top5.iteritems():
        country_code.append(country)
        b = [i.encode("utf-8") for i in a]
        time = [datetime.datetime.strptime(i, time_format) for i in b]
        dates = matplotlib.dates.date2num(time)
        x = []
        x.append(time[0])
        i = 0
        time.sort()
        y = []
        x = [datetime.datetime(2017, 3, 13, 12, 50, 18)]
        while i <= len(time):
            prevs_time = x[-1]
            prevs_time
            print prevs_time
            newtime = x[-1] + datetime.timedelta(hours=1)
            if (newtime > time[-1]):
                break
            x.append(newtime)
            no = count(prevs_time, x[-1], time)
            y.append(no)
        del x[0]
        plt.plot(x, y)
    plt.gcf().autofmt_xdate()
    plt.legend([i for i in country_code], loc='upper left')
    plt.xlabel('Time(days)')
    plt.ylabel('Packets/hour')
    plt.title('Top 5 Countries')
    plt.show()


def top5_countries():
    with open('country_uni.txt') as f:
        country_time= json.load(f)
    d_descending = sorted(countries, key=countries.get, reverse=True)
    k = 0
    for i,j in country_time.iteritems():
        print i,len(j)
    d_descending = ['CN','VN','US','BR','TW']
    for i in d_descending:
        if k < 5:
            top5[i] = country_time[i]
        k += 1
    #for i,j in top5.iteritems():
     #   print i,len(j)
    plot_graph(top5)





def main():
    '''if len(sys.argv) > 2:
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
    json.dump(country_ts, f)'''
    top5_countries()

if __name__ == '__main__':
    main()
