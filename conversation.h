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
        char id[ID_LEN];
        char name[NAME_LEN];
        char faculty[FACULTY_LEN];
};

struct conversation {
        conversation_type type;
        vector<struct student_info> info_list;
};

#endif
