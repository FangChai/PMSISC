extern "C" {
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
#include <map>
#include <mutex>
#include <algorithm>
#include "csismp_limits.h"
#include "csismp_session.h"
#include "csismp_timer.h"
#include "csismp_collector.h"
#include "csismp_sender.h"
#include "csismp_config.h"


using namespace std;

static struct mac_configure config;
static pcap_t* descr;

//local function prototypes
static inline uint32_t tlvs_len(const vector<struct tlv>& tlvs);
static inline void send_raw(uint8_t* dgram, int size);
static void send_dgram(const vector<struct tlv>& tlvs, struct control_code cntl, const uint8_t dest_mac[]);

static inline uint32_t tlvs_len(const vector<struct tlv>& tlvs)
{
        uint32_t result = 0;
        for(auto iter = tlvs.begin(); iter != tlvs.end(); ++iter)
                result += iter->len + TLV_HEAD_LEN;

        return result;
}

static inline void send_raw(uint8_t* dgram, int size)
{
#ifndef DEBUG
        if(-1 == pcap_sendpacket(descr, dgram, size))
                perror("send failure");
#else
        FILE *fp = fopen("out_packet", "w");
        fwrite(dgram, size, 1, fp);
#endif
}

static void send_dgram(const vector<struct tlv>& tlvs, struct control_code cntl, const uint8_t dest_mac[])
{
        uint32_t dgram_len;
        uint8_t* dgram;
        uint8_t* curr;

        dgram_len = tlvs_len(tlvs) + sizeof(struct ether_header) + CONTROL_LEN;
        dgram = (uint8_t *)malloc(dgram_len);
        memset(dgram, 0, dgram_len);

        //construct the etherc header
        curr = dgram;
        for(int i = 0; i < 6; ++i) {
                dgram[i] = dest_mac[i];
                dgram[i+6] = config.local_mac[i];
        }
        curr += 12;

        curr[0] = 0x11;
        curr[1] = 0x22;
        curr += 2;

        //construct the control field
        *(uint32_t *)curr = htobe32(cntl.slice_nr);
        curr[0] = cntl.type;
        curr[1] |= cntl.begin ? 0x80 : 0x00;
        curr[1] |= cntl.end ? 0x40 : 0x00;
        curr+=4;

        *(uint32_t *)curr = htobe32(cntl.session_id);
        curr+=4;

        //construct the tlvs field
        for(auto iter = tlvs.begin(); iter != tlvs.end(); ++iter) {
                if(0 == iter->type) {
                        curr[0] = 0x00;
                        curr[1] = 0x00;
                        break;
                }

                curr[0] = iter->type;
                curr[1] = iter->len;
                strcpy((char *)(curr + TLV_HEAD_LEN), iter->data.c_str());
                curr += iter->len + TLV_HEAD_LEN;
        }

        send_raw(dgram, dgram_len);

        free(dgram);
}

int send_session(const struct session& s)
{
        struct control_code cntl;
        uint8_t curr_state;  //0, 1, 2 : id, name, faulty
        uint32_t curr_size, curr_nr;
        vector<struct tlv> tlvs;

        cntl.type = s.type;
        cntl.session_id = s.session_id;

        //process ACK and RJT
        if(cntl.type == SESSION_ACK || cntl.type == SESSION_RJT) {
                vector<struct tlv> tlvs;
                tlvs.push_back({TLV_END, 0, ""});
                cntl.begin = 1;
                cntl.end = 1;
                cntl.slice_nr = 0;
                send_dgram(tlvs, cntl, s.source_mac);
        }

        curr_state = 0;
        curr_size = 0;
        curr_nr = 0;
        auto iter = s.info_list.begin();
        while(iter != s.info_list.end()) {


                if(0 == curr_state) {
                        if(curr_size + iter->id.size() + 3 + TLV_HEAD_LEN > MAX_TLVS_LEN) {
                                tlvs.push_back({TLV_END, 0, ""});

                                cntl.begin = curr_nr ? 0 : 1;
                                cntl.end = 0;
                                cntl.slice_nr = curr_nr;

                                send_dgram(tlvs, cntl, s.source_mac);

                                curr_nr++;
                                tlvs.clear();
                                curr_size = 0;
                                continue;
                        }

                        tlvs.push_back( {TLV_ID, (uint8_t)(iter->id.size()+1), iter->id} );
                        curr_size += iter->id.size() + 1 + TLV_HEAD_LEN;

                } else if(1 == curr_state) {
                        if(curr_size + iter->name.size() + 3 + TLV_HEAD_LEN > MAX_TLVS_LEN) {
                                tlvs.push_back({TLV_END, 0, ""});

                                cntl.begin = curr_nr ? 0 : 1;
                                cntl.end = 0;
                                cntl.slice_nr = curr_nr;

                                send_dgram(tlvs, cntl, s.source_mac);

                                curr_nr++;
                                tlvs.clear();
                                curr_size = 0;
                                continue;
                        }

                        tlvs.push_back( {TLV_NAME, (uint8_t)(iter->name.size()+1), iter->name} );
                        curr_size += iter->name.size() + 1 + TLV_HEAD_LEN;

                } else if(2 == curr_state) {
                        if(curr_size + iter->faculty.size() + 3 + TLV_HEAD_LEN > MAX_TLVS_LEN) {
                                tlvs.push_back({TLV_END, 0, ""});

                                cntl.begin = curr_nr ? 0 : 1;
                                cntl.end = 0;
                                cntl.slice_nr = curr_nr;

                                send_dgram(tlvs, cntl, s.source_mac);

                                curr_nr++;
                                tlvs.clear();
                                curr_size = 0;
                                continue;
                        }

                        tlvs.push_back( {TLV_FACULTY, (uint8_t)(iter->faculty.size()+1), iter->faculty} );
                        if( (iter + 1) == s.info_list.end()) {
                                tlvs.push_back({TLV_END, 0, ""});

                                cntl.begin = curr_nr ? 0 : 1;
                                cntl.end = 1;
                                cntl.slice_nr = curr_nr;

                                send_dgram(tlvs, cntl, s.source_mac);

                        }

                        curr_size += iter->faculty.size() + 1 + TLV_HEAD_LEN;
                        iter++;
                }

                curr_state = (curr_state + 1) % 3;
        }
}

void init_sender()
{
        config = mac_configure("Config.txt");
        char errbuf[PCAP_ERRBUF_SIZE];
        string dev = get_dev();

        descr = pcap_open_live(dev.c_str(), BUFSIZ, 1, 0, errbuf);

        if(NULL == descr) {
                printf("pcap_open_live(): %s\n",errbuf);
                exit(1);
        }

}
