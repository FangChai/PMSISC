extern "C"{
#include <pthread.h>
}
#include <iostream>
#include <vector>
#include <iterator>
#include <ctime>
#include <csignal>
#include "conversation.h"
#include "csismp_limits.h"


pthread_t thread_cast_data;
using namespace std;


vector<student_info> local_data;
pthread_mutex_t local_data_mutex;

void process_conversation(conversation *conv)
{
    switch(conv->type){
        case conversation_type::CONVERSATION_ADD:
            {
                pthread_mutex_lock(&local_data_mutex);
                copy(conv->info_list.begin(),conv->info_list.end(),back_inserter(local_data));
                pthread_mutex_unlock(&local_data_mutex);
            }
            break;
        case conversation_type::CONVERSATION_DEL:
            break;
        case conversation_type::CONVERSATION_ACK:
            break;
        case conversation_type::CONVERSATION_RJT:
            break;
        default:
            break;
    }
}
void *cast_data(void *arg)
{
    pthread_mutex_lock(&local_data_mutex);
    pthread_mutex_unlock(&local_data_mutex);
    pthread_exit(NULL);
}
void *on_timer_up(void *arg)
{
    int ret=pthread_create(&my_thread,NULL,&cast_data,NULL);
    if(ret){
        cerr<<"ERROR OCCURED WHEN CREATING THREAD : "<<ret<<endl;
        exit(EXIT_FAILURE);
    }
    pthread_exit(NULL);
}
