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
#include <cstdlib>
#include <deque>
#include "session.h"
#include "csismp_limits.h"
#include "csismp_sender.h"

using namespace std;


static deque<student_info> local_data;
static deque<student_info> sync_data;
static pthread_mutex_t local_data_mutex;

static thread indiv_timer;
static bool sync_started=0;

void Timer_Send();

bool check_valid(session to_check)
{
        stable_sort(to_check.info_list.begin(),to_check.info_list.end(),[](const student_info &a,const student_info &b)
                    {
                            return a.id<b.id;
                    });
        if(unique(to_check.info_list.begin(),to_check.info_list.end(),[](const student_info &a ,const student_info &b)
                  {
                          return a.id==b.id;
                  })!=to_check.info_list.end()){
                return false;
        }
        return true;
}
void build_student_session(session & to_build,session_type type,size_t size)
{
        srand(time(0)+1547566);
        to_build.session_id=(rand() % 100000) + 1000;
        to_build.type=type;
        for(size_t i=0;i<size;++i){
                int _id=rand() % 100000 ;
                student_info info;
                info.id=to_string(_id);
                info.name="Suzumiya Haruhi";
                info.faculty="Literature";
                to_build.info_list.push_back(info);
        }
}
void print_all_students(){
        time_t local_time=time(0);
        char tmp[32];
        strftime(tmp,sizeof(tmp),"%H:%M:%S",localtime(&local_time));
        string time(tmp);
        FILE * fp;
        fp=fopen("StuInfo.txt","w");
        fprintf(fp,"Time : %s\nFaculty                             Student ID       Name\n",time.data());
        fprintf(fp,"--------------------------------------------------------------------------------\n");
        for(int i=0;i<local_data.size();i++){
                int line=(local_data[i].faculty.size()-1)/33;if(line<0)line=0;
                for(int j=0;j<line;j++){
                        for(int k=j*33;k<(j+1)*33;k++)
                                fprintf(fp,"%c",local_data[i].faculty[k]);
                        fprintf(fp,"\n");
                }
                for(int j=line*33;j<local_data[i].faculty.size();j++)
                        fprintf(fp,"%c",local_data[i].faculty[j]);
                for(int j=local_data[i].faculty.size();j<(line+1)*33;j++)
                        fprintf(fp," ");
                fprintf(fp,"   %s",local_data[i].id.data());
                for(int j=local_data[i].id.size();j<17;j++)
                        fprintf(fp," ");
                fprintf(fp,"%s\n",local_data[i].name.data());
        }
        for(int i=0;i<sync_data.size();i++){
                int line=(sync_data[i].faculty.size()-1)/33;if(line<0)line=0;
                for(int j=0;j<line;j++){
                        for(int k=j*33;k<(j+1)*33;k++)
                                fprintf(fp,"%c",sync_data[i].faculty[k]);
                        fprintf(fp,"\n");
                }
                for(int j=line*33;j<sync_data[i].faculty.size();j++)
                        fprintf(fp,"%c",sync_data[i].faculty[j]);
                for(int j=sync_data[i].faculty.size();j<(line+1)*33;j++)
                        fprintf(fp," ");
                fprintf(fp,"   %s",sync_data[i].id.data());
                for(int j=sync_data[i].id.size();j<17;j++)
                        fprintf(fp," ");
                fprintf(fp,"%s\n",sync_data[i].name.data());
        }

        fprintf(fp,"--------------------------------------------------------------------------------\n");
        fclose(fp);
}
session construct_ackmsg(session * _session)
{
        session ret;
        ret.type=session_type::SESSION_ACK;
        ret.session_id=_session->session_id;
        for(int i=0;i<6;++i){
                ret.source_mac[i]=_session->source_mac[i];
        }

        return ret;
}
session construct_rjtmsg(session * _session)
{
        session ret;
        ret.type=session_type::SESSION_RJT;
        ret.session_id=_session->session_id;
        for(int i=0;i<6;++i){
                ret.source_mac[i]=_session->source_mac[i];
        }
        return ret;
}
void process_session(session *conv)
{
        printf("started process session %d\n",conv->session_id);

        switch(conv->type){
        case session_type::SESSION_ADD:
        {
                if(check_valid(*conv)){
                        pthread_mutex_lock(&local_data_mutex);
                        copy(conv->info_list.begin(),conv->info_list.end(),front_inserter(local_data));
                        stable_sort(local_data.begin(),local_data.end(),[](const student_info &a,const student_info &b)
                                    {
                                            return a.id<b.id ;
                                    });
                        size_t update_count=0;
                        auto new_end=unique(local_data.begin(),local_data.end(),[&] (const student_info &a,const student_info &b)
                                            {
                                                    if(a.id==b.id&&a.name==b.name&&a.faculty==b.faculty)
                                                        update_count++;
                                                    return a.id==b.id;
                                            });
                        if(update_count!=local_data.end()-new_end)
                                print_all_students();
                        local_data.erase(new_end,local_data.end());
                        pthread_mutex_unlock(&local_data_mutex);
                        session ack_msg=construct_ackmsg(conv);
                        send_session(ack_msg);

                        //if first add succeed, start the timer
                        if(!sync_started){
                                sync_started=true;
                                indiv_timer=thread(Timer_Send);
                                printf("timer started\n");
                        }

                }
                else {
                        session rjt_msg=construct_rjtmsg(conv);
                        send_session(rjt_msg);
                }
        }
        break;
        case session_type::SESSION_DEL:
        {
                if(check_valid(*conv)){
                        bool success=true;
                        pthread_mutex_lock(&local_data_mutex);
                        for_each(conv->info_list.begin(),conv->info_list.end(),[&](const student_info &info)
                                 {
                                         if(success){
                                                 bool success_once=false;
                                                 for(auto iter=local_data.begin();iter!=local_data.end();++iter){
                                                         if(iter->id==info.id){
                                                                 iter=local_data.erase(iter);
                                                                 success_once=true;
                                                         }
                                                 }
                                                 if(!success_once) success=false;
                                         }
                                 });
                        pthread_mutex_unlock(&local_data_mutex);
                        if(!success){
                                session rjt_msg=construct_rjtmsg(conv);
                                send_session(rjt_msg);
                        }
                        else {
                                session ack_msg=construct_ackmsg(conv);
                                send_session(ack_msg);
                                print_all_students();
                        }
                }
        }
        break;
        case session_type::SESSION_ACK:
                break;
        case session_type::SESSION_RJT:
                break;
        case session_type::SESSION_SYN:
        {
                copy(conv->info_list.begin(),conv->info_list.end(),front_inserter(sync_data));
                stable_sort(sync_data.begin(),sync_data.end(),[](const student_info &a,const student_info &b)
                            {
                                    return a.id<b.id;
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
void *on_timer_up()
{
        printf("time_up\n");
        session broadcast_session;
        broadcast_session.type=session_type::SESSION_SYN;
        pthread_mutex_lock(&local_data_mutex);
        broadcast_session.info_list.assign(local_data.begin(),local_data.end());
        pthread_mutex_unlock(&local_data_mutex);
        srand(time(0)+123764);
        broadcast_session.session_id=1000+(rand() % 100001);
        broadcast_session.source_mac[0]=0x01;
        broadcast_session.source_mac[1]=0x80;
        broadcast_session.source_mac[2]=0xC2;
        broadcast_session.source_mac[3]=0xDD;
        broadcast_session.source_mac[4]=0xFE;
        broadcast_session.source_mac[5]=0xFF;

        send_session(broadcast_session);
        //TODO
        //Send MSG.
}
void Timer_Send()
{
        for(;;){
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                on_timer_up();
        }
}

