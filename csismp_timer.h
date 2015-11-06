#ifndef TIMER_H
#define TIMER_H

#include "csismp_collector.h"
#include "csismp_session.h"

int init_timer(void (*func)(mac_id_pair_t, session_type));
int add_timer(mac_id_pair_t p, session_type type);
int del_timer(mac_id_pair_t p);

#endif
