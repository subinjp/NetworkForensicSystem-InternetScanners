#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>

#define ETHERNET_SIZE 14
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void identify_packets(const u_char*,int);
struct sockaddr_in source,dest;
long long int tcp=0,udp=0,icmp=0,unknown_prt=0,igmp=0,total=0;
int num_ips=0;
char devs_ipaddr[50][50];
int main()
{
    pcap_if_t *alldevsp, *device;
    pcap_addr_t *devs_addr;
    pcap_t *handle;
    char errbuf[100],*ip;
    int count=0;
    char *filter_exp="not(host 192.68.167.130)";
    bpf_u_int32 netmask;
    struct  bpf_program fp;
    pcap_dumper_t *dumpfile;
    char *filename = "./pcap/capture.pcap";
    char devs[50][50];
    if(-1 == pcap_findalldevs(&alldevsp,errbuf))
    {
        printf("Error Finding devices:%s",errbuf);
        exit(1);
    }
    else if(0 == pcap_findalldevs(&alldevsp,errbuf))
    {
        for(device=alldevsp;device!=NULL;device=device->next)
        {
            printf("%d. %s - %s\n",count,device->name,device->description);

            if(device->name != NULL)
                strcpy(devs[count],device->name);

            /*Get the ip address associated with network device*/
            for(devs_addr=device->addresses;devs_addr!=NULL;devs_addr=devs_addr->next)
            {

                if(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr)!=NULL){

                    if(strcmp(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr),"192.68.167.130") == 0 ||
                       strcmp(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr),"2.0.0.0") == 0 ||
                       strcmp(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr),"127.0.0.1") == 0 ||
                       strcmp(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr),"0.0.0.0") == 0 ||
                       strcmp(inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr),"1.0.0.0") == 0){

                        continue;
                    }

                    strcpy(devs_ipaddr[num_ips],inet_ntoa(((struct sockaddr_in*)devs_addr->addr)->sin_addr));
                    printf("Ip address-%s\n",devs_ipaddr[num_ips]);
                    num_ips++;
                }
            }
            count++;
        }
    }
    // open capture device
    handle = pcap_open_live(devs[0],65536,1,0,errbuf);

    if(handle == 0){

        fprintf(stderr,"Not able to open the device-%s : %s \n",devs[0],errbuf);
        exit(1);
    }
    //To check whether we are capturing packets on Ethernet device
    if(pcap_datalink(handle) != DLT_EN10MB){

        fprintf(stderr,"%s is not Ethernet",devs[0]);
        exit(1);
    }
    /* Compile the filter expressions*/
    if(pcap_compile(handle,&fp,filter_exp,0,netmask) == -1){

        fprintf(stderr,"Could not compile the filter expression %s :%s \n",filter_exp,pcap_geterr(handle));
        exit(1);
    }

    /* Install compiled filter*/
    if(pcap_setfilter(handle,&fp) == -1){

        fprintf(stderr,"Could not apply the compiled filter expression %s: %s \n",filter_exp,pcap_geterr(handle));
        exit(1);
    }

    /*Open the capture file to save the packets*/
    dumpfile = pcap_dump_open(handle,filename);
    if(dumpfile == NULL){

        fprintf(stderr,"Error opening capture file\n");
        exit(1);
    }

     /*Setting the callback function*/
    pcap_loop(handle,-1,process_packet,(unsigned char*)dumpfile);
    return 0;
}

/*Here we dissect packet in to different headers and process it*/
void process_packet(u_char * dumpfile,const struct pcap_pkthdr* header,const u_char* packet){

    int j=0;
    static int m=0;
    pcap_t *p;
    p = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dump[24];
    if(m==0){
        int k=131;
        for(j=0;j<25;j++){
            char buffer[32]; // The filename buffer.
            snprintf(buffer,sizeof(char)*32,"./pcap/capture%i.pcap",k);
            dump[j] = pcap_dump_open(p,buffer);
            k++;
        }
    }
    m=1;



    /*Packet consists of ethernet header+ip header+tcp/udp header+payload

      ip_header - Gets the first address of the ip header after ethernet header
    */
    int size = header->len;
    struct iphdr* ip_header=(struct iphdr*)(packet +ETHERNET_SIZE);
    ++total;
    /*Check the protocol and increment number of such packets*/
    switch (ip_header->protocol)
    {
        case 1:  //ICMP Protocol
            ++icmp;
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            break;

        case 17: //UDP Protocol
            ++udp;
            break;

        default: //Some Other Protocol like ARP etc.
            ++unknown_prt;
            break;
    }
    printf("TCP : %lld   UDP : %lld   ICMP : %lld   IGMP : %lld   Others: %lld   Total : %lld\r", tcp , udp , icmp , igmp , unknown_prt , total);

    /*save all packets to the output file */
    pcap_dump(dumpfile,header,packet);

    /*Convert source IP address from struct iphdr* to struct in_addr(from struct socketaddr_in) */
    memset(&source,0,sizeof(source));
    source.sin_addr.s_addr=ip_header->saddr;

    /*Convert destination IP address from struct iphdr* to struct in_addr(from struct socketaddr_in) */
    memset(&dest,0,sizeof(dest));
    dest.sin_addr.s_addr=ip_header->daddr;

    /*dump packets from different ip addresses in to seperate files*/
    if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.131") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.131") == 0){

            pcap_dump((unsigned char*)dump[0],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.132") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.132") == 0){

            pcap_dump((unsigned char*)dump[1],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.133") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.133") == 0){

            pcap_dump((unsigned char*)dump[2],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.134") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.134") == 0){

            pcap_dump((unsigned char*)dump[3],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.135") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.135") == 0){

            pcap_dump((unsigned char*)dump[4],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.136") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.136") == 0){

            pcap_dump((unsigned char*)dump[5],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.137") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.137") == 0){

            pcap_dump((unsigned char*)dump[6],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.138") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.138") == 0){

            pcap_dump((unsigned char*)dump[7],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.139") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.139") == 0){

            pcap_dump((unsigned char*)dump[8],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.140") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.140") == 0){

            pcap_dump((unsigned char*)dump[9],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.141") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.141") == 0){

            pcap_dump((unsigned char*)dump[10],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.142") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.142") == 0){

            pcap_dump((unsigned char*)dump[11],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.143") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.143") == 0){

            pcap_dump((unsigned char*)dump[12],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.144") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.144") == 0){

            pcap_dump((unsigned char*)dump[13],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.145") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.145") == 0){

            pcap_dump((unsigned char*)dump[14],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.146") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.146") == 0){

            pcap_dump((unsigned char*)dump[15],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.147") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.147") == 0){

            pcap_dump((unsigned char*)dump[16],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.148") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.148") == 0){

            pcap_dump((unsigned char*)dump[17],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.149") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.149") == 0){

            pcap_dump((unsigned char*)dump[18],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.150") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.150") == 0){

            pcap_dump((unsigned char*)dump[19],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.151") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.151") == 0){

            pcap_dump((unsigned char*)dump[20],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.152") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.152") == 0){

            pcap_dump((unsigned char*)dump[21],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.153") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.153") == 0){

            pcap_dump((unsigned char*)dump[22],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.154") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.154") == 0){

            pcap_dump((unsigned char*)dump[23],header,packet);
    }
    else if(strcmp(inet_ntoa(source.sin_addr),"192.68.167.155") == 0 ||
       strcmp(inet_ntoa(dest.sin_addr),"192.68.167.155") == 0){

            pcap_dump((unsigned char*)dump[24],header,packet);
    }

    //identify_packets(packet,size);
}

/*Identify the packets and its behavior*/
void identify_packets(const u_char* packet,int size){

    struct iphdr* ip_header=(struct iphdr*)(packet +ETHERNET_SIZE);

    if(ntohs(ip_header->id) == 54321){
        printf("Zmap Scanner\n");
    }


}
