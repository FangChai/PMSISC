#ifndef CONVERSATION_H
#define CONVERSATION_H

#include <vector>
#include <cinttypes>
#include "csismp_limits.h"

using namespace std;

enum session_type {
        CONVERSATION_ADD,
        CONVERSATION_DEL,
        CONVERSATION_ACK,
        CONVERSATION_RJT,
        CONVERSATION_SYN
};

struct student_info {
        string id;
        string name;
        string faculty;
};

struct session {
        uint32_t session_id;
        session_type type;
        vector<struct student_info> info_list;
};

#endif
