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
#include <mutex>
#include <algorithm>
#include "csismp_limits.h"
#include "session.h"
#include "timer.h"
#include "csismp_collector.h"


using namespace std;


static const uint8_t sync_mac[6] = {0x01, 0x80, 0xc2, 0xdd, 0xfe, 0xff};
static map<uint32_t, struct slice_set> session_map;
static struct mac_configure configure;
static pthread_mutex_t collector_mtx;


bool cmp_slice(const struct slice& a, const struct slice& b)
{
        return a.slice_nr < b.slice_nr;
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

//get control code, and adjust the byte order
void parse_control(struct control_code* ctrl, const uint8_t* raw)
{
        ctrl->type = (session_type)raw[0];
        ctrl->begin = raw[1] & 0x80 ? 1 : 0;
        ctrl->end = raw[1] & 0x40 ? 1 : 0;

        ctrl->slice_nr = 0;
        ctrl->slice_nr = *((uint32_t *) (raw));
        ctrl->slice_nr = ctrl->slice_nr & htobe32(0x003fffff);
        ctrl->slice_nr = be32toh(ctrl->slice_nr);

        ctrl->session_id = *((uint32_t *) (raw + 4));
        ctrl->session_id = be32toh(ctrl->session_id);
}

void forget_session(uint32_t id)
{
        pthread_mutex_trylock(&collector_mtx); //signal handler should not be blocked

        session_map.erase(id);

        pthread_mutex_unlock(&collector_mtx);
}

int get_tlv(struct tlv* t,  const uint8_t* raw)
{
        t->type = (tlv_type) raw[0];
        switch(raw[0]) {
        case TLV_END:
                return 2;
                break;

        case TLV_ID:
                t->len = raw[1];
                if(raw[1 + t->len] != '\0' || t->len > ID_LEN || t->len < 2)
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        case TLV_NAME:
                t->len = raw[1];
                if(raw[1 + t->len] != '\0' || t->len > NAME_LEN || t->len < 2)
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        case TLV_FACULTY:
                t->len = raw[1];
                if(raw[1 + t->len] != '\0' || t->len > FACULTY_LEN || t->len < 2)
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        default :
                return -1;
                break;
        }

}

int construct_session(uint32_t id, struct session* s, session_type type)
{
        struct slice_set& slc_set = session_map[id];
        uint8_t curr_state = 0;    //0, 1, 2 : id, name, faculty

        s->session_id = id;
        s->type = type;

        sort(slc_set.slices.begin(), slc_set.slices.end(), cmp_slice);
        if(type == SESSION_ADD) {
                curr_state = 0;
                struct student_info stu_info;

                for(auto iter1 = slc_set.slices.begin(); iter1 != slc_set.slices.end(); ++iter1) {
                        for(auto iter2 = iter1->tlvs.begin(); iter2 != iter1->tlvs.end(); ++iter2) {
                                if(0 == curr_state) {
                                        if(iter2->type != TLV_ID)
                                                return -1;
                                        stu_info.id = iter2->data;
                                } else if(1 == curr_state) {
                                        if(iter2->type != TLV_NAME)
                                                return -1;
                                        stu_info.name = iter2->data;
                                } else if(2 == curr_state) {
                                        if(iter2->type != TLV_FACULTY)
                                                return -1;
                                        stu_info.faculty = iter2->data;

                                        s->info_list.push_back(stu_info);
                                }

                                curr_state = (curr_state + 1) % 3;

                        }
                }
        } else if(type == SESSION_DEL) {
                struct student_info stu_info;

                for(auto iter1 = slc_set.slices.begin(); iter1 != slc_set.slices.end(); ++iter1) {
                        for(auto iter2 = iter1->tlvs.begin(); iter2 != iter1->tlvs.end(); ++iter2) {
                                if(iter2->type != TLV_ID)
                                        return -1;
                                stu_info.id = iter2->data;

                                s->info_list.push_back(stu_info);
                        }
                }

        }

        return 0;
}

int process_dgram(const uint8_t* raw, int len)
{
        const uint8_t* curr = raw;
        int remain = len;
        struct control_code cntl_cd;
        struct slice slc;
        uint8_t err_flag, end_flag;


        parse_control(&cntl_cd, curr);
        curr += CONTROL_LEN;
        remain -= CONTROL_LEN;

        slc.slice_nr = cntl_cd.slice_nr;

        //if meet a new session, contruct a bed for it
        pthread_mutex_lock(&collector_mtx);

        if(session_map.find(cntl_cd.session_id) == session_map.end()) {

                struct slice_set sset;

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

        struct slice_set& slc_set = session_map[cntl_cd.session_id];
        if(cntl_cd.end)
                slc_set.total = cntl_cd.slice_nr + 1;

        slc_set.slices.push_back(slc);
        if((slc_set.total != 0) &&  (slc_set.slices.size() == slc_set.total)) {
                struct session s;

                if(construct_session(cntl_cd.session_id, &s, cntl_cd.type) == -1) {
                        forget_session(cntl_cd.session_id);
                        return -1;
                }
//CALL CFB                process_session(&s);
                forget_session(cntl_cd.session_id);

        }

        pthread_mutex_unlock(&collector_mtx);

        return 0;
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

                        if(-1 == process_dgram(buffer+sizeof(struct ethhdr), n-sizeof(struct ethhdr)))
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

        uint8_t test_dgram[BUFFER_SIZE];
        char c;
        size_t len;
        while(EOF != (c = getchar()))
        {
                test_dgram[len++] = c;
        }
        process_dgram(test_dgram+sizeof(struct ethhdr), len);

        return 0;
}
