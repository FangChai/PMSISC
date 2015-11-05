#include "csismp_collector.h"
#include "csismp_sender.h"
#include "csismp_process.h"
#include "mac_configure.h"
#include <cstdlib>
#include <vector>
#include <cstdio>
#include <string>

extern "C" {
#include <unistd.h>
}

using namespace std;
extern void send_dgram(const vector<struct tlv>& tlvs, struct control_code cntl, const uint8_t dest_mac[]);

int main()
{

        struct session s;
        struct mac_configure config("Config.txt");
        struct tlv t;
        vector<struct tlv> ts;

        uint8_t dest_mac[6];
        for(int i = 0; i < 6; ++i){
                s.source_mac[i] = config.dest_macs[0][i];
                dest_mac[i] = config.dest_macs[0][i];
        }

        init_sender();
        getchar();
        puts("time out\n");
        ts.clear();
        ts.push_back({TLV_NAME, strlen("foo_bar") + 1, "foo_bar"});
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_ADD, 0, 0, 1, 1234}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 0, 0, 3, 1234}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 0, 0, 2, 1234}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 1, 0, 0, 1234}, dest_mac);
        sleep(6);
        send_dgram(ts, {SESSION_ADD, 0, 1, 4, 1234}, dest_mac);
        getchar();

        puts("slice_nr abnormal\n");
        ts.clear();
        ts.push_back({TLV_NAME, strlen("foo_bar") + 1, "foo_bar"});
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_ADD, 0, 0, 1, 1235}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 0, 0, 3, 1235}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 0, 0, 2, 1235}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 1, 0, 10086, 1235}, dest_mac);
        send_dgram(ts, {SESSION_ADD, 0, 1, 4, 1235}, dest_mac);
        getchar();

        puts("unknown tlv type\n");
        ts.clear();
        ts.push_back({(tlv_type)6, strlen("foo_bar") + 1, "foo_bar"});
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_ADD, 1, 1, 0, 1236}, dest_mac);
        getchar();

        puts("tlv length\n");
        ts.clear();
        ts.push_back({TLV_NAME, strlen("foo_bar") + 3, "foo_bar"});
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_ADD, 1, 1, 0, 1237}, dest_mac);
        getchar();

        puts("tlv no end\n");
        ts.clear();
        ts.push_back({TLV_NAME, strlen("foo_bar") + 1, "foo_bar"});
        send_dgram(ts, {SESSION_ADD, 1, 1, 0, 1238}, dest_mac);
        getchar();

        puts("del students that don't exsist\n");
        puts("add\n");
        s.type = SESSION_ADD;
        build_student_session(s, SESSION_ADD, 10);
        send_session(s);
        getchar();

        puts("del\n");
        ts.clear();
        ts.push_back({TLV_ID, strlen("11")+1, "11"});
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_DEL, 1, 1, 0, 1239}, dest_mac);

        getchar();
        puts("add students 0~99");
        s.type = SESSION_ADD;
        s.session_id = 0x1111;
        char temp[1024];
        s.info_list.clear();
        for(int i = 0; i  < 100; i++) {
                sprintf(temp, "%d", i);
                s.info_list.push_back({string(temp), "foo_" + string(temp), "Information Security"});
        }
        send_session(s);

        getchar();
        puts("add students 0~99, again");
        s.type = SESSION_ADD;
        s.session_id = 0x2222;

        s.info_list.clear();
        for(int i = 0; i  < 100; i++) {
                sprintf(temp, "%d", i);
                s.info_list.push_back({string(temp), "foo_" + string(temp), "Information Security"});
        }
        send_session(s);

        getchar();
        puts("del students 44~66");

        ts.clear();
        for(int i = 44; i  < 67; i++) {
                sprintf(temp, "%d", i);
                ts.push_back({TLV_ID, strlen(temp) + 1, string(temp)});
        }
        ts.push_back({TLV_END, 0, ""});
        send_dgram(ts, {SESSION_DEL, 1, 1, 0, 0x3333}, dest_mac);


        getchar();
        puts("sync students 404~502");
        s.type = SESSION_SYN;
        s.session_id = 0x4444;

        s.info_list.clear();
        for(int i = 404; i  < 503; i++) {
                sprintf(temp, "%d", i);
                s.info_list.push_back({string(temp), "foo_" + string(temp), "Information Security"});
        }
        send_session(s);


        getchar();
        puts("add students 0~99, with modifications");
        s.type = SESSION_ADD;
        s.session_id = 0x2222;

        s.info_list.clear();
        for(int i = 0; i  < 100; i++) {
                sprintf(temp, "%d", i);
                s.info_list.push_back({string(temp), "bar__" + string(temp), "Information Security"});
        }
        send_session(s);

        return EXIT_SUCCESS;
}
