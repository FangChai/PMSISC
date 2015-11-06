#ifndef CSISMP_PROCESS_H
#define CSISMP_PROCESS_H

#include "session.h"

void build_student_session(session & to_build,session_type type,size_t size);
void process_session(session *conv);
void Timer_Send();

#endif
