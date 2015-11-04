#ifndef SESSION_H
#define SESSION_H

#include <vector>
#include <cinttypes>
#include "csismp_limits.h"

using namespace std;

enum session_type {
        SESSION_ADD = 1,
        SESSION_DEL,
        SESSION_ACK,
        SESSION_RJT,
        SESSION_SYN
};

struct student_info {
        string id;
        string name;
        string faculty;
};

struct session {
        uint32_t session_id;
        uint8_t* source_mac[6];
        session_type type;
        vector<struct student_info> info_list;
};

#endif
