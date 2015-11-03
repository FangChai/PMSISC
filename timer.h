#ifndef TIMER_H
#define TIMER_H

int init_timer(void (*func)(uint32_t));
int add_timer(uint32_t id);
int del_timer(uint32_t id);

#endif
