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
#include "session.h"
#include "csismp_limits.h"


using namespace std;


deque<student_info> local_data;
deque<student_info> sync_data;
pthread_mutex_t local_data_mutex;
void laozidehanshu(const deque<student_info>&infos,const string&time){
    printf("Time : %s\nFaculty                             Student ID       Name\n",time.data());
    printf("--------------------------------------------------------------------------------\n");
    for(int i=0;i<infos.size();i++){
        int line=(infos[i].faculty.size()-1)/33;if(line<0)line=0;
        for(int j=0;j<line;j++){
            for(int k=j*33;k<(j+1)*33;k++)
                printf("%c",infos[i].faculty[k]);
            printf("\n");
        }
        for(int j=line*33;j<infos[i].faculty.size();j++)
            printf("%c",infos[i].faculty[j]);
        for(int j=infos[i].faculty.size();j<(line+1)*33;j++)
            printf(" ");
        printf("   %s",infos[i].id.data());
        for(int j=infos[i].id.size();j<17;j++)
            printf(" ");
        printf("%s\n",infos[i].name.data());
    }
    printf("--------------------------------------------------------------------------------\n");
}
void print_all_students();
session construct_ackmsg(uint32_t session_id)
{
    session ret;
    ret.type=session_type::SESSION_ACK;
    ret.session_id=session_id;
    return ret;
}
session construct_rjtmsg(uint32_t session_id)
{
    session ret;
    ret.type=session_type::SESSION_RJT;
    ret.session_id=session_id;
    return ret;
}
void process_session(session *conv)
{
    switch(conv->type){
        case session_type::SESSION_ADD:
            {
                pthread_mutex_lock(&local_data_mutex);
                copy(conv->info_list.begin(),conv->info_list.end(),front_inserter(local_data));
                stable_sort(local_data.begin(),local_data.end(),[](const student_info &a,const student_info &b)
                        {
                            return a.id<b.id ;
                        });
                auto new_end=unique(local_data.begin(),local_data.end(),[] (const student_info &a,const student_info &b)
                        {
                            return a.id==b.id;
                        });
                local_data.erase(new_end,local_data.end());
                pthread_mutex_unlock(&local_data_mutex);
                print_all_students();
                session ack_msg=construct_ackmsg(conv->session_id);
                //TODO:
                //Send MSG.
            }
            break;
        case session_type::SESSION_DEL:
            {
                 pthread_mutex_lock(&local_data_mutex);
                 for_each(conv->info_list.begin(),conv->info_list.end(),[&](const student_info &info)
                    {
                        bool success=false;
                        for(auto iter=local_data.begin();iter!=local_data.end();++iter){
                            if(iter->id==info.id){
                                if(iter->name!=info.name || iter->faculty!= info.faculty)
                                    break;
                                iter=local_data.erase(iter);
                                success=true;
                                break;
                            }
                        }
                        if(!success){
                            session rjt_msg=construct_rjtmsg(conv->session_id);
                            //TODO:
                            //Send MSG.
                        }
                        else {
                            session ack_msg=construct_ackmsg(conv->session_id);
                            //TODO:
                            //Send MSG.
                        }
                    });
            }
            print_all_students();
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
void print_all_students()
{
}
void test_print()
{
    cout<<"======================================="<<endl;
    for_each(local_data.begin(),local_data.end(),[](student_info& a)
            {
                cout<<a.id+"\t"+a.name+"\t"+a.faculty<<endl;
            });
    cout<<"======================================="<<endl;
    for_each(sync_data.begin(),sync_data.end(),[](student_info& a)
            {
                cout<<a.id+"\t"+a.name+"\t"+a.faculty<<endl;
            });
    cout<<"======================================="<<endl;
}
void *on_timer_up()
{
    session broadcast_session;
    broadcast_session.type=session_type::SESSION_SYN;
    pthread_mutex_lock(&local_data_mutex);
    broadcast_session.info_list.assign(local_data.begin(),local_data.end());
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
//Test purpose.
int main()
{
    //Construct test data.
    session test_session;
    test_session.session_id=10001;
    test_session.type=session_type::SESSION_ADD;
    test_session.info_list.push_back({"123123123","Yukinoshita Yukino","Mathematics"});
    test_session.info_list.push_back({"123123124","Utaha Senpai","Literature"});
    test_session.info_list.push_back({"123123125","Hachiman","Education"});
    process_session(&test_session);
    test_print();
    test_session.info_list.clear();
    test_session.info_list.push_back({"123123123","Miyakami Yuuki","Metaphysics & Chinese Kongfu & Literature"});
    test_session.info_list.push_back({"123123125","Toma Kazura","Piano Performing"});
    test_session.info_list.push_back({"123123124","Kagami Rin","Modern Music"});
    process_session(&test_session);
    test_print();
    test_session.info_list.clear();
    test_session.info_list.push_back({"123123125","Toma Kazura","Piano Performing"});
    test_session.type=session_type::SESSION_DEL;
    process_session(&test_session);
    test_print();
    laozidehanshu(local_data,"22:22:22");
    return 0;
}
