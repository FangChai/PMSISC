#ifndef CONVERSATION_H
#define CONVERSATION_H

#include <vector>
#include "csismp_limits.h"

using namespace std;

enum conversation_type {
        CONVERSATION_ADD,
        CONVERSATION_DEL,
        CONVERSATION_ACK,
        CONVERSATION_RJT
};

struct student_info {
        string id;
        string name;
        string faculty;
};

struct conversation {
        conversation_type type;
        vector<struct student_info> info_list;
};

#endif
