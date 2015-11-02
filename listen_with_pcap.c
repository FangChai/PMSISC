#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#define CSISMP_ADDR_LEN 6
#define SIZE_CSISMP 14

#define FRAG_NO_BIT_LEN 22
#define SESSION_ID_LEN 4
#define SIZE_CONTROL 8
#define TLV_MAX_LEN 64

#define ADD_DATA_MSG 1
#define DEL_DATA_MSG 2
#define ACK_MSG 3
#define RJT_MSG 4
#define SYNC_MSG 5


struct mac_addr{
    uchar addr[6];
}
struct csismp_header{
    uchar dhost[CSISMP_ADDR_LEN];
    uchar shost[CSISMP_ADDR_LEN];
    ushort protocol_type;
};
struct csismp_control{
    uchar type;
    bool  isbegin;
    bool  isend;
    bool  fragno[FRAG_NO_BIT_LEN];
    uchar  sessionID[SESSION_ID_LEN];
};
struct tlv{
    uchar type;
    uchar len;
    uchar value[TLV_MAX_LEN];
};
typedef tlvs *tlv;

struct mac_addr* listening_addrs;
struct mac_addr send_addr;

bool check_packet(const struct csismp_header *packet)
{

    return true;
}
void got_packet(uchar* args,const struct pcap_pkthdr *header,const u_char *packet)
{
    const struct csismp_header *header;
    const struct tlvs *payload;
    const struct csismp_control *control;
    header=(struct csismp_header *)packet;
    control=(struct csismp_control*)(packet+SIZE_CSISMP);
    payload=(const char *)(packet+SIZE_CSISMP+SIZE_CONTROL);
    if(check_packet(header)){//Check the dest mac addr .
        //Actual work goes here.
    }
}
int main(int argc,char* argv[])
{
    char *dev,errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    dev=pcap_lookupdev(errbuf);
    if(dev==NULL){
        fprintf(stderr,"No default device found: %s\n",errbuf);
        return 2;
    }
    printf("Device : %s\n",dev);
    handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
        return 2;
    }
    //Enter the loop.
    pcap_loop(handle,-1,got_packet,"");
    return 0;
}
