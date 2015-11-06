#include "csismp_session.h"
#include <cstdio>
#include <iostream>
#include <string>

using namespace std;

void print_session(const struct session& s)
{
        cout<<string(80, '=')<<endl;
        cout<<"ID: "<<s.session_id<<endl;
        cout<<"From: ";
        for(int i = 0; i < 6; ++i)
                printf("%2x", s.source_mac[i]);
        cout<<endl;

        for(auto iter = s.info_list.begin(); iter != s.info_list.end(); ++ iter) {
                printf("Name: %s\n"
                       "ID: %s\n"
                       "Faculty: %s\n"
                       ,iter->name.c_str(), iter->id.c_str(), iter->faculty.c_str());
        }

        cout<<string(80, '=')<<endl;
}
