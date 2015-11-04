#ifndef CSISMP_COLLECTOR_H
#define CSISMP_COLLECTOR_H

#include <vector>
#include <string>
#include <cinttypes>

using namespace std;

#define BUFFER_SIZE 2048
#define CONTROL_LEN 8
#define CSISMP_PROTO 0x1122

enum tlv_type {
        TLV_END = 0,
        TLV_ID,
        TLV_NAME,
        TLV_FACULTY
};

struct control_code {
        session_type type;
        uint8_t begin;
        uint8_t end;
        uint32_t slice_nr;
        uint32_t session_id;
};

struct tlv {
        tlv_type type;
        uint8_t len;
        string data;
};

struct slice {
        int slice_nr;
        vector<struct tlv> tlvs;
};

struct slice_set {
        uint32_t total;
        vector<struct slice> slices;
};

#endif
