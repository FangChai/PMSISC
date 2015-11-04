#ifndef TIMER_H
#define TIMER_H

#include "csismp_collector.h"

int init_timer(void (*func)(mac_id_pair_t));
int add_timer(mac_id_pair_t p);
int del_timer(mac_id_pair_t p);

#endif
