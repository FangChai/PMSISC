extern "C"{
#include <pthread.h>
}
#include <thread>
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <csignal>
#include <deque>
#include "conversation.h"
#include "csismp_limits.h"


using namespace std;


deque<student_info> local_data;
deque<student_info> sync_data;
pthread_mutex_t local_data_mutex;

void print_all_students();
void process_conversation(conversation *conv)
{
    switch(conv->type){
        case conversation_type::CONVERSATION_ADD:
            {
                pthread_mutex_lock(&local_data_mutex);
                copy(conv->info_list.begin(),conv->info_list.end(),front_inserter(local_data));
                stable_sort(local_data.begin(),local_data.end(),[](const student_info &a,const student_info &b)
                        {
                            return a.id<b.id || a.id==b.id;
                        });
                auto new_end=unique(local_data.begin(),local_data.end(),[] (const student_info &a,const student_info &b)
                        {
                            return a.id==b.id;
                        });
                local_data.erase(new_end,local_data.end());
                pthread_mutex_unlock(&local_data_mutex);
            }
            print_all_students();
            break;
        case conversation_type::CONVERSATION_DEL:
            {
                 pthread_mutex_lock(&local_data_mutex);
                 for_each(conv->info_list.begin(),conv->info_list.end(),[](const student_info &info)
                    {
                        bool success=false;
                        for(auto iter=local_data.begin();iter!=local_data.end();++iter){
                            if(iter->id==info.id){
                                iter=local_data.erase(iter);
                                success=true;
                                break;
                            }
                        }
                        if(!success){
                        //TODO
                        //Construct &Send RJT MSG.
                        }
                        else {
                        //TODO
                        //Construct &Send ACK MSG.
                        }
                    });
            }
            print_all_students();
            break;
        case conversation_type::CONVERSATION_ACK:
            break;
        case conversation_type::CONVERSATION_RJT:
            break;
        case conversation_type::CONVERSATION_SYN:
            {
                copy(conv->info_list.begin(),conv->info_list.end(),front_inserter(sync_data));
                stable_sort(sync_data.begin(),sync_data.end(),[](const student_info &a,const student_info &b)
                        {
                            return a.id<b.id || a.id==b.id;
                        });
                auto new_end=unique(sync_data.begin(),sync_data.end(),[] (const student_info &a,const student_info &b)
                        {
                            return a.id==b.id;
                        });
                sync_data.erase(new_end,sync_data.end());
            }
            break;
        default:
            break;
    }
}
void print_all_students()
{
    ofstream ofs("StuInfo.txt");

    ofs.close();
}
void *on_timer_up()
{
    conversation session;
    session.type=conversation_type::CONVERSATION_SYN;
    pthread_mutex_lock(&local_data_mutex);
    session.info_list.assign(local_data.begin(),local_data.end());
    pthread_mutex_unlock(&local_data_mutex);
    //TODO
    //Send MSG.
}
void Timer_Send()
{
    for(;;){
        std::this_thread::sleep_for(std::chrono::milliseconds(30000));
        on_timer_up();
    }
}

