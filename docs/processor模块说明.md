#CSISMP
##Implementation by team *One Week Friends*
###Documentation for processor part
####1.数据结构
在被划分为Processor的逻辑部分(aka `csismp_process.h`   `csismp_process.cpp`),为了存储本校区学生信息，并实现多线程读写，使用了以下代码
>`static deque<student_info> local_data;`  
>`static pthread_mutex_t local_data_mutex;`

用来表示单个本地学生信息的数据结构`student_info`定义如下
>` struct student_info { 
         string id; 
         string name; 
         string faculty; 
 }; `

`local_data_mutex` 为 **POSIX threads** 互斥锁，用于实现多线程的读写。  
  
为了存储其他校区的学生信息，使用了以下稍加复杂的代码  
>`static map<MacAddr,deque<student_info>> sync_data;`  
>`static pthread_mutex_t sync_data_mutex;`  
  
MacAddr为一个自定义的，存储mac地址的数据类型，sync_data使得某特定校区mac映射到其对应的`deque<student_info>`，方便使校区之间的数据隔离进行确认和操作，保证后续操作的准确性。
  
当然，在`sync_data_mutex`的支持下，这一切都是支持多线程的。

####2.函数
#####对外提供的接口

>`void* process_session(void *conv);`  
>`void init_processor();`  
  
`process_session`被**collector part**调用，并且传入已经抽象并填充完全的一个`session`，由此函数负责释放内存，删除传入的session以防止内存泄漏。 当然，这个函数的主要功能是完全的处理这个`session`,并且负责发送所有的高级AKC报文和RJT报文。

`init_processor`被main部分调用，用于初始化互斥锁，并与其他部分的代码保持一致。
#####相对重要的内部函数
>`static void print_all_students()`  
>`static void Timer_Send()`  
>`static void *on_timer_up()`  
  
如同其字面意义一样，`print_all_student`的作用是输出全部学生信息到文件**StuInfo.txt**中，在相应条件下被调用。  
  
`Timer_Send`非常有趣，它在被创建线程后，将会傻乎乎的一直以30秒为周期调用`on_timer_up`，发送同步报文，直至程序死掉。
***
*Copyright Reserved.*