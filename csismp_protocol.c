extern "C" {
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

}

#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>
#include "csismp_limits.h"
#include "conversation.h"

#define BUFFER_SIZE 2048

using namespace std;

struct control_code {
        uint8_t type;
        uint8_t begin;
        uint8_t end;
        uint32_t  slice;
        uint32_t id;
};

struct tlv {
        uint8_t type;
        uint8_t len;
        union v {
                char id[ID_LEN];
                char name[NAME_LEN];
                char faculty[FACULTY_LEN];
        };
};

struct mac_configure {
        uint8_t dest_macs[256][6];
        size_t  list_len;
        uint8_t local_mac[6];
};

static const uint8_t sync_mac[6] = {0x01, 0x80, 0xc2, 0xdd, 0xfe, 0xff};
static map<int, struct conversation> conversation_list;
static struct mac_configure configure;


void parse_control(struct control_code* ctrl, const uint8_t *raw)
{
        ctrl->type = raw[0];
        ctrl->begin = raw[1] & ((uint8_t)1) << 1;
        ctrl->end = raw[1] & ((uint8_t)1) << 2;

        ctrl->slice = 0;
        ctrl->slice = *((uint32_t *) (raw + 1));
        ctrl->slice = ctrl->slice >> 3;
        ctrl->slice = ctrl->slice & (0xffffffff << 22);

        ctrl->id = *((uint32_t *) (raw + 4));
}

int cmp_mac(const uint8_t mac1[], const uint8_t mac2[])
{
        int result = 0;
        for(int i = 0; i < 6; i++) {
                if(mac1[i] != mac2[i]) {
                        result = mac1[i] - mac2[i];
                        break;
                }
        }

        return result;
}
void parse_raw_packet(struct csismp_packet *packet, const char *raw, int len)
{
}

void parse_conversation(const struct csismp_packet *packet_list[], int list_len)
{
}

void get_slice()
{
}

int is_interesting(const ethhdr* eth_hdr)
{
        if(!cmp_mac(eth_hdr->h_source, configure.local_mac))
                return 0;

        //broadcast
        if(!cmp_mac(eth_hdr->h_dest, sync_mac))
                return 1;

        for(size_t i = 0; i < configure.list_len; ++i) {
                if(!cmp_mac(eth_hdr->h_dest, configure.dest_macs[i]))
                        return 1;
        }

        return 0;
}

int read_loop()
{
        int packet_sock;
        char buffer[BUFFER_SIZE];
        struct ethhdr* eth_hdr;

        if(0 > (packet_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
                perror("socket");
                exit(1);
        }

        while(1){
                int n;
                n = recv(packet_sock, buffer, sizeof(buffer), 0);

                eth_hdr = (struct ethhdr *) buffer;
                if(is_interesting(eth_hdr)) {
                        puts("\n");
                }
        }

}

int main()
{
        configure.dest_macs[0][0] = 0x40;
        configure.dest_macs[0][1] = 0xe2;
        configure.dest_macs[0][2] = 0x30;
        configure.dest_macs[0][3] = 0xff;
        configure.dest_macs[0][4] = 0x22;
        configure.dest_macs[0][5] = 0x35;
        configure.list_len++;

        read_loop();
        return 0;
}
