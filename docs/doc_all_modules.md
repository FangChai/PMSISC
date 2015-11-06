#CSISMP
##Implementation by team *One Week Friends*
###Documentation for all modules
####collector模块
#####数据结构
	enum tlv_type { 
        TLV_END = 0,  
        TLV_ID,  
        TLV_NAME,
        TLV_FACULTY
	};

	struct control_code {
        session_type type;
        uint8_t begin;
        uint8_t end;
        uint32_t slice_nr;
        uint32_t session_id;
	};

	struct tlv {
        tlv_type type;
        uint8_t len;
        string data;
	};

	struct slice {
        int slice_nr;
        vector<struct tlv> tlvs;
	};

	struct slice_set {
        uint32_t total;
        vector<struct slice> slices;
	};

`typedef pair<vector<uint8_t>, uint32_t> mac_id_pair_t;`

`static map<mac_id_pair_t, struct slice_set> session_map;`   

>mac_session-id对与当前收到的slices的映射  

`static struct mac_configure configure;` 
>配置文件
`static pthread_mutex_t collector_mtx;` 
>互斥锁，用于控制临界区访问（即上面两个全局数据）  
  
  


#####主要函数功能描述：
`static void parse_control(struct control_code* ctrl, const uint8_t* raw);` 
>从原始报文里提取控制域
`static int process_dgram(const uint8_t* raw, int len, uint8_t source_mac[]);` 
>处理原始报文,解析报文各个部分并填入相应的数据结构中
`static int construct_session(mac_id_pair_t p, struct session* s, session_type type);` 
>将slices整合成session
`static int get_tlv(struct tlv* t,  const uint8_t* raw, int32_t len);` 
>从原始报文中提取一个tlv
`void start_collector();` 
>模块入口点，用于初始化与启动收包循环
`static void collector(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);` 
>pcap loop的回调函数，过滤包，处理包过长等错误  
  
  

####processor模块


####sender模块
#####主要函数功能描述：
`int send_session(const struct session& s);` 
>将session分成大小合理的tlvs合集，以供后续包装使用
`static inline uint32_t tlvs_len(const vector<struct tlv>& tlvs);`
>统计tlvs中所有tlv占最终报文的长度
`static inline void send_raw(uint8_t* dgram, int size);` 
>发送最终报文
`static void send_dgram(const vector<struct tlv>& tlvs, struct control_code cntl, const uint8_t dest_mac[]);`
>构造最终报文各部分并整合  
  
  

####timer模块
#####数据结构：
`static map<mac_id_pair_t, uint32_t> timer_map;` 
>mac-session-id对及其当前经过时间的记录
`static map<mac_id_pair_t, session_type> type_map;` 
>mac-session-id对及其会话类型记录  

#####主要函数功能描述：
`static void time_out(int sig);` 
>本进程的sigalarm函数，每秒运行10次，检测是否有时钟到时，通知回调函数收割超时会话
`int init_timer(void (*func)(mac_id_pair_t, session_type));` 
>初始化进程时钟
`int add_timer(mac_id_pair_t p, session_type type);` 
>增加会话追踪
`int del_timer(mac_id_pair_t p);` 
>移除会话追踪  
  
  

####config模块
#####数据结构：
`uint8_t dest_macs[256][6];`  
>存储监听mac
`size_t  list_len;` 
>监听mac地址的数量
`uint8_t local_mac[6];` 
>本地mac
#####主要函数功能描述：
`mac_configure(const string&s);` 
>读取文件名为s的配置文件，按要求处理，并填入数据
`void Write(const string&s);` 
>按格式要求写入输出配置文件










