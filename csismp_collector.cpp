extern "C" {
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <endian.h>
}

#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>
#include <mutex>
#include <string>
#include "csismp_limits.h"
#include "session.h"
#include "timer.h"

#define BUFFER_SIZE 2048
#define CONTROL_LEN 8
#define CSISMP_PROTO 0x1122

enum tlv_type {
        TLV_END = 0,
        TLV_ID,
        TLV_NAME,
        TLV_FACULTY
}

using namespace std;

struct control_code {
        uint8_t type;
        uint8_t begin;
        uint8_t end;
        uint32_t slice_nr;
        uint32_t session_id;
};

struct tlv {
        tlv_type type;
        uint8_t len;
        union v {
                string id;
                string name;
                string faculty;
        };
};

struct slice {
        int slice_nr;
        vector<struct tlv> tlvs;
};

struct slice_set {
        uint32_t total;
        vector<struct slice> slices;
};

struct mac_configure {
        uint8_t dest_macs[256][6];
        size_t  list_len;
        uint8_t local_mac[6];
};

static const uint8_t sync_mac[6] = {0x01, 0x80, 0xc2, 0xdd, 0xfe, 0xff};
static map<uint32_t, struct slice_set> session_map;
static struct mac_configure configure;

static pthread_mutex_t collector_mtx;


//get control code, and adjust the byte order
void parse_control(struct control_code* ctrl, const uint8_t* raw)
{
        ctrl->type = raw[0];
        ctrl->begin = raw[1] & 0x80 ? 1 : 0;
        ctrl->end = raw[1] & 0x40 ? 1 : 0;

        ctrl->slice_nr = 0;
        ctrl->slice_nr = *((uint32_t *) (raw));
        ctrl->slice_nr = ctrl->slice_nr & htobe32(0x003fffff);
        ctrl->slice_nr = be32toh(ctrl->slice_nr);

        ctrl->id = *((uint32_t *) (raw + 4));
        ctrl->id = be32toh(ctrl->id);
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

void forget_session(uint32_t id)
{
        pthread_mutex_trylock(&collector_mtx); //signal handler should not be blocked

        session_map.erase(id);

        pthread_mutex_unlock(&collector_mtx);
}

int get_tlv(struct tlv* t,  uint8* raw)
{
        t->type = raw[0];
        switch(raw[0]) {
        case TLV_END:
                return 0;
                break;

        case TLV_ID:
                t->len = raw[1];
                if(raw[2 + t->len] != '\0' || t->len > ID_LEN || t->len < 2)
                        return - 1;

                t->v.id = string(raw[3], t->len - 2);

                return t->len + 2;
                break;

        case TLV_NAME:
                t->len = raw[1];
                if(raw[2 + t->len] != '\0' || t->len > NAME_LEN || t->len < 2)
                        return - 1;

                t->v.name = string(raw[3], t->len - 2);

                return t->len + 2;
                break;

        case TLV_FACULTY:
                t->len = raw[1];
                if(raw[2 + t->len] != '\0' || t->len > FACULTY_LEN || t->len < 2)
                        return - 1;

                t->v.faculty = string(raw[3], t->len - 2);

                return t->len + 2;
                break;

        default :
                return -1;
                break;
        }

}
int process_dgram(const uint8_t* raw, int len)
{
        const uint8_t* curr = raw;
        int remain = len;
        struct control_code cntl_cd;
        struct slice slc;
        struct slice_set slc_set;
        uint8_t err_flag, end_flag;


        parse_control(&cntl_cd, curr);
        curr += CONTROL_LEN;
        remain -= CONTROL_LEN;

        slc.slice_nr = cntl_cd.slice_nr;

        //if meet a new session, contruct a bed for it
        pthread_mutex_lock(&collector_mtx);

        if(slices_statistics.find(cntl_cd.session_id) == slices_statistics.end()) {

                struct slice_set sset;

                sset.current = 0;
                sset.total = 0;
                session_map[cntl_cd.session_id] = sset;

                add_timer(cntl_cd.session_id);
        }

        pthread_mutex_unlock(&collector_mtx);

        //decompose the raw dgram to tlvs
        err_flag = end_flag = 0;
        while(remain > 0) {

                struct tlv t;
                uint8_t len = get_tlv(&t, curr);

                if( -1 == len) {
                        err_flag = 1;
                        break;
                } else {
                        if(t.type == TLV_END){
                                end_flag = 1;
                                break;
                        } else if(t.type == TLV_FACULTY
                                  || t.type == TLV_ID
                                  || t.type == TLV_NAME ) {

                                slc.tlvs.push_back(t);
                        }

                        remain -= len;
                        curr += len;
                }
        }

        //if encountered error, report to the caller
        if(err_flag || !end_flag) {
                forget_session(cntl_cd.session_id);
                return -1;
        }


        //update the corresponding slice_set

        pthread_mutex_lock(&collector_mtx);

        &slc_set = session_map[cntl_cd.session_id];
        if(cntl_cd.end)
                slc_set.total = cntl_cd.slice_nr;

        if((slc_set.total != 0) &&  (slc_set.slices.size() == slc_set.total)) {
                struct session con;

                con.session_id = session_id
                
        }

        pthread_mutex_unlock(&collector_mtx);

}

int is_interesting(const ethhdr* eth_hdr)
{
        if( eth_hdr->h_proto != CSISMP_PROTO || !cmp_mac(eth_hdr->h_source, configure.local_mac))
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
void send_rjt()
{
}
int collect_loop()
{
        int packet_sock;
        uint8_t buffer[BUFFER_SIZE];
        struct ethhdr* eth_hdr;

        if(0 > (packet_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
                perror("socket");
                exit(1);
        }

        for(;;) {
                int n;

                n = recv(packet_sock, buffer, sizeof(buffer), 0);
                if( n >= MAX_DGRAM_LEN)
                        send_rjt();

                eth_hdr = (struct ethhdr *) buffer;
                if(is_interesting(eth_hdr)) {

                        if( -1 = process_dgram(buffer + sizeof(struct ethhdr), n - sizeof(struct ethhdr)) )
                                send_rjt();
                }
        }

}

void init_collector()
{
        pthread_mutex_init(&collector_mtx, NULL);
        init_timer(forget_session);
}

void destroy_collector()
{
        pthread_mutex_destroy(&collector_mtx);
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

        uint8_t test_dgram[8]= {0x01,0xc0,0,0,0,0,0,0x01};
        process_dgram(test_dgram);

        return 0;
}
