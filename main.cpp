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

char* dev;

void usage() {
    printf("syntax: SendArp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: SendArp eth0 192.168.0.2 192.168.0.3\n");
}

void getMACAddr(char *addr)
{
    FILE *fp = NULL;
    char *IP = addr;
    char *cmd = "ping -c 1 \0";
    printf("%s\n%s\n",cmd,IP);
    char command[100];
    strcat(cmd,command);
    strcat(IP,command);
    printf("%s",command);
    if((fp=popen(command,"r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        exit(1);
    }

    pclose(fp);

    char* line;

    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {
        printf("%s",line);
    }


    //return strcat(cmd,IP);

}

const char* getGatewayAddr()
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
           //printf("ptr : %s\n",ptr);
           printf("%s",ptr);
           return ptr;
       }
   }

   fprintf(stderr,"We couldn't find Gateway!");
   exit(1);
}

//void packet_lookup(char* sender_IP, char* target_IP)
//{

//    char errbuf[PCAP_ERRBUF_SIZE];
//    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
//    if (handle == nullptr) {
//        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
//        exit(1);
//    }

//    EthArpPacket packet;
//    char* target_MAC = findMAC(target_IP);
//    char* sender_MAC = findMAC(sender_IP);

//    packet.eth_.dmac_ = Mac(target_MAC);   // you
//    packet.eth_.smac_ = Mac(sender_MAC);   // me
//    packet.eth_.type_ = htons(EthHdr::Arp);

//    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
//    packet.arp_.pro_ = htons(EthHdr::Ip4);
//    packet.arp_.hln_ = Mac::SIZE;
//    packet.arp_.pln_ = Ip::SIZE;
//    packet.arp_.op_ = htons(ArpHdr::Reply);
//    packet.arp_.smac_ = Mac(sender_MAC);   //me
//    packet.arp_.sip_ = htonl(Ip(findGateway));        //gate
//    packet.arp_.tmac_ = Mac(target_MAC);   //you
//    packet.arp_.tip_ = htonl(Ip(target_IP));        //you

//    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

//    if (res != 0) {
//        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
//    }

//    pcap_close(handle);
//}

int main(int argc, char* argv[]) {

//    int i;
//    int attackCase =0;
//       printf("%d\n",argc);
//       for(i=0;i<argc;i++)
//       {
//           printf("%s\n",argv[i]);
//       }

//    if (argc >=4 && argc%2==0) {
//        usage();
//        return -1;
//    }

//    dev = argv[1];

//    attackCase = (argc -2)/2;
//    for (i=0;i<attackCase;i++)
//    {
//        packet_lookup(argv[2+i],argv[3+i]);
//    }

      printf("Gateway : %s\n" ,getGatewayAddr());

//    getMACAddr(argv[2]);
}

