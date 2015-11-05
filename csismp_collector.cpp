extern "C" {
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <endian.h>
#include <pcap.h>
}

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <algorithm>
#include <utility>
#include <cstring>
#include "csismp_limits.h"
#include "session.h"
#include "timer.h"
#include "csismp_collector.h"
#include "csismp_sender.h"
#include "csismp_process.h"
#include "mac_configure.h"


#define DEBUG

#ifdef DEBUG
extern void print_session(const struct session& s);
#endif

using namespace std;

static const uint8_t sync_mac[6] = {0x01, 0x80, 0xc2, 0xdd, 0xfe, 0xff};
static map<mac_id_pair_t, struct slice_set> session_map;
static struct mac_configure configure;
static pthread_mutex_t collector_mtx;
static bool sync_started = 0;


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

string get_dev()
{
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];
        string result;

        #ifdef DEBUG
        return "wlp3s0";
        #endif

        if(pcap_findalldevs(&alldevs, errbuf) == -1)
        {
                fprintf(stderr,"Error in pcap_findalldevs_ex: %s/n", errbuf);
                exit(1);
        }

        for(d = alldevs->next; d != NULL; d = d->next)
        {
                if(result.size() == 0 && strcmp(d->name, "any")) {
                        result = string(d->name);
                        continue;
                } else if(strcmp(d->name, result.c_str()) <=0
                              &&(strcmp(d->name, "any")))
                        result = string(d->name);
        }

        pcap_freealldevs(alldevs);

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

void forget_session(mac_id_pair_t p)
{
        pthread_mutex_trylock(&collector_mtx); //signal handler should not be blocked
        session_map.erase(p);
        pthread_mutex_unlock(&collector_mtx);

}

void reject_session(mac_id_pair_t p)
{
        struct session rjt_s;

        //if all read forgotten, then we don't care
        if(session_map.end() == session_map.find(p))
                return;

        rjt_s.type = SESSION_RJT;
        for(int i = 0; i < 6; i++)
                rjt_s.source_mac[i] = p.first[i];

        rjt_s.session_id = p.second;
        send_session(rjt_s);
        forget_session(p);
        printf("reject %d\n", p.second);

}

int get_tlv(struct tlv* t,  const uint8_t* raw, int32_t len)
{
        t->type = (tlv_type) raw[0];
        switch(raw[0]) {
        case TLV_END:
                if(raw[1] == 0 && len == 2)
                        return 2;
                else
                        return -1;
                break;

        case TLV_ID:
                t->len = raw[1];
                if((raw[1 + t->len] != '\0') || (t->len > ID_LEN)
                   || (t->len < 2) || (len  < t->len  + TLV_HEAD_LEN))
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        case TLV_NAME:
                t->len = raw[1];
                if((raw[1 + t->len] != '\0') || (t->len > NAME_LEN)
                   || (t->len < 2) || (len  < t->len + TLV_HEAD_LEN))
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        case TLV_FACULTY:
                t->len = raw[1];
                if((raw[1 + t->len] != '\0') || (t->len > FACULTY_LEN)
                   || (t->len < 2) || (len < t->len + TLV_HEAD_LEN))
                        return - 1;
                t->data = string((const char *)(raw+2), t->len - 1);
                return t->len + 2;
                break;

        default :
                return -1;
                break;
        }

}

int construct_session(mac_id_pair_t p, struct session* s, session_type type)
{
        struct slice_set& slc_set = session_map[p];
        uint8_t curr_state = 0;    //0, 1, 2 : id, name, faculty
        uint32_t prev_slice_nr;    //for validation checking

        s->session_id = p.second;
        s->type = type;

        for(int i = 0; i < 6; ++i)
                s->source_mac[i] = p.first[i];

        sort(slc_set.slices.begin(), slc_set.slices.end(), cmp_slice);

        //check the validation of the slice_nrs
        prev_slice_nr = slc_set.slices.begin()->slice_nr;
        for(auto iter = slc_set.slices.begin() + 1; iter != slc_set.slices.end(); ++prev_slice_nr, ++iter) {
                if((prev_slice_nr + 1) != iter->slice_nr)
                        return -1;
        }

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

int process_dgram(const uint8_t* raw, int len, uint8_t source_mac[])
{
        const uint8_t* curr = raw;
        int remain = len;
        struct control_code cntl_cd;
        struct slice slc;
        vector<uint8_t> mac;
        mac_id_pair_t mcid_pair;
        uint8_t err_flag, end_flag;

        parse_control(&cntl_cd, curr);
        curr += CONTROL_LEN;
        remain -= CONTROL_LEN;

        slc.slice_nr = cntl_cd.slice_nr;

        pthread_mutex_lock(&collector_mtx);

        //construct the pair specifying this session
        for(int i = 0; i < 6; i++) {
                mcid_pair.first.push_back(source_mac[i]);
        }
        mcid_pair.second = cntl_cd.session_id;

        //if meet a new session, contruct a bed for it
        if(session_map.find(mcid_pair) == session_map.end()) {

                struct slice_set sset;

                sset.total = 0;
                session_map[mcid_pair] = sset;

                add_timer(mcid_pair);
        }


        pthread_mutex_unlock(&collector_mtx);

        if(len + sizeof(struct ether_header) > MAX_DGRAM_LEN) {
                puts("slice too long\n");
                reject_session(mcid_pair);
                return -1;
        }

        //decompose the raw dgram to tlvs
        err_flag = end_flag = 0;
        while(remain > 0) {

                struct tlv t;
                uint8_t len = get_tlv(&t, curr, remain);

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
                reject_session(mcid_pair);
                return -2;
        }

        //update the corresponding slice_set

        pthread_mutex_lock(&collector_mtx);
        struct slice_set& slc_set = session_map[mcid_pair];
        if(cntl_cd.end)
                slc_set.total = cntl_cd.slice_nr + 1;

        slc_set.slices.push_back(slc);
        if((slc_set.total != 0) &&  (slc_set.slices.size() == slc_set.total)) {
                struct session s;

                //fill id, type, info_list, mac, check the slice_nr
                if(construct_session(mcid_pair, &s, cntl_cd.type) < 0) {
                        reject_session(mcid_pair);
                        pthread_mutex_unlock(&collector_mtx);
                        return -3;
                }

                process_session(&s);

                #ifdef DEBUG
                print_session(s);
                #endif

                forget_session(mcid_pair);

        }

        pthread_mutex_unlock(&collector_mtx);
        printf("mac ");
        for(int i = 0; i < 6; ++i) {
                printf("%2x", mcid_pair.first[i]);
        }
        printf(", id %d, slice %d, begin: %d, end: %d\n", mcid_pair.second, cntl_cd.slice_nr, cntl_cd.begin, cntl_cd.end);
        printf("slc_set status: total %d, current %d\n", slc_set.total, slc_set.slices.size());
        putchar('\n');

        return 0;
}

int is_interesting(const ether_header* eth_hdr)
{
        if(ntohs(eth_hdr->ether_type) != CSISMP_PROTO || !cmp_mac(eth_hdr->ether_shost, configure.local_mac))
                return 0;

        //broadcast
        if(!cmp_mac(eth_hdr->ether_dhost, sync_mac))
                return 1;

        for(size_t i = 0; i < configure.list_len; ++i) {
                if(!cmp_mac(eth_hdr->ether_dhost, configure.dest_macs[i]))
                        return 1;
        }

        return 0;
}

void collector(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

        struct ether_header* eth_hdr;

        eth_hdr = (struct ether_header *) buffer;
/*
        printf("Grabbed buffer of length %d\n",header->len);
        printf("Ethernet address length is %d\n", 6);
        auto eptr = (struct ether_header *) buffer;
        int i;
        printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        auto ptr = eptr->ether_dhost;
        i = ETHER_ADDR_LEN;
        printf(" Destination Address: ");
        do{

                printf("%s%x",(i == 6) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");
        ptr = eptr->ether_shost;
        i = ETHER_ADDR_LEN;
        printf(" Source Address: ");
        do{
                printf("%s%x",(i == 6) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");
*/
        if(is_interesting(eth_hdr)) {
                process_dgram(buffer+sizeof(struct ether_header), header->len-sizeof(struct ether_header), eth_hdr->ether_shost);
        }

}

void start_collector()
{
        string dev;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* descr;

        //set up the lock and the timer
        pthread_mutex_init(&collector_mtx, NULL);
        init_timer(reject_session);

        //read config
        configure = mac_configure("Config.txt");

        //set up pcap
        dev = get_dev();

        descr = pcap_open_live(dev.c_str(), BUFSIZ, 1, 0, errbuf);

        if(NULL == descr) {
                printf("pcap_open_live(): %s\n",errbuf);
                exit(1);
        }

        pcap_loop(descr, -1, collector, NULL);

}

void destroy_collector()
{
        pthread_mutex_destroy(&collector_mtx);
}
