extern "C" {
#include <unistd.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
}

#include <map>
#include <set>
#include <thread>
#include "timer.h"

#define OUT_TIME 50

using namespace std;



static map<uint32_t, uint32_t> timer_map;
static void (*call_back)(uint32_t);
static uint32_t max_time;

static void time_out(int sig)
{

        for(auto iter = timer_map.begin(); iter != timer_map.end(); ++iter) {
                iter->second++;
        }

        for(auto iter = timer_map.begin(); iter != timer_map.end(); ++iter) {
                if(iter->second >= OUT_TIME) {
                         call_back(iter->first);
                         del_timer(iter->first);
                 }
        }
}

int init_timer(void (*func)(uint32_t))
{
        struct itimerval tmr_val;

        tmr_val.it_interval.tv_sec = 0;
        tmr_val.it_interval.tv_usec = 100000;
        tmr_val.it_value.tv_sec = 0;
        tmr_val.it_value.tv_usec = 100000;
        signal(SIGALRM, time_out);
        setitimer(ITIMER_REAL, &tmr_val, NULL);
        call_back = func;

        return 1;
}


int add_timer(uint32_t id)
{
        timer_map[id] = 0;
}

int del_timer(uint32_t id)
{
        auto iter_found  = timer_map.find(id);
        if(timer_map.end() != iter_found) {
                timer_map.erase(id);
        }
}
