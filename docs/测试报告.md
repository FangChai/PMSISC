#CSISMP
##Implementation by team *One Week Friends*
###Test Reports
####1.基础配置

输入：`Config.txt`  
  
期望输出：`CfgInfo.txt`(MAC大写按字典序排列）  

>测试结果  ：**正确**

####2.接收并解析CSISMP数据报文
#####rjt处理

######超时检测  
输入：`slice1`，`slice3`，`slice2`，`slice0`（begin），**五秒停顿**，`slice4`（end）  

期望输出：两次`rjt`，`session id` 与源id**一致**，mac与源mac**一致**  

>测试结果  ：**正确**

######分片号异常  
输入：`slice1`，`slice10086`，`slice2`，`slice0（begin）`，`slice4（end）`   
 
期望输出：两次`rjt`，`session id`与源`id`**一致**，mac与源mac**一致**   

>测试结果  ：**正确**

######不认识的tlv类型
输入：`slice0（begin，end）``（tlvtype = 6）`  

期望输出：`rjt`  

>测试结果  ：**正确**   

######tlv长度过长
*>1024* 

输入：`slice0``（begin，end）` 总长度1060  

期望输出：`rjt`

>测试结果  ：**正确**  
  
*长度与tlvlen描述不符*  

输入：`slice0（begin，end）``tlvtype` = 1，`tlv_len`=13  

期望输出：`rjt`  

>测试结果  ：**正确**  

*字符串不包含'\0'*  

输入：`slice0（begin，end）``tlvtype`= 1，`tlv_len`=11,`data`="012345678901234"  

期望输出：`rjt`  

>测试结果  ：**正确**  

######没有结束tlv  

输入：`slice0`（begin，end）no tlv  

期望输出：`rjt`  

>测试结果  ：**正确**   

######删除不存在的学生  

输入：`session0`  

*add,包含10个学生信息，学号0~9*  

`session1` 
*`del`,包含一个`id`，学号`11`*  

期望输出：`rjt`  

>测试结果  ：**正确**    


#####学生信息管理以及同步报文发送还有StuInfo.txt输出
*以下所有输入在单次运行内按顺序输入，且不超时*  

输入：`add_session`  
  
*增加100个学生，学号0~99*  

期望输出：`ack`，30秒后的同步报文 ，`StuInfo.txt ` 

>测试结果  ：**正确**    

输入：`add_session`  
*增加100个学生，学号0~99，信息有变动*  

期望输出：`ack`，30秒后的同步报文 ，`StuInfo.txt ` 

>测试结果  ：**正确**    


输入：`del_session`  
*删除44~66学号的学生*    

期望输出：`ack`，30秒后的同步报文 ，`StuInfo.txt ` 

>测试结果  ：**正确**    


输入：`sync_session`   

*来自其它校区的学生，学号 404~502*  

期望输出：30秒后的同步报文，`StuInfo.txt`

>测试结果  ：**正确**    

输入：`sync_session`   

*来自与上个校区同校区的学生，学号 404~502，信息有变动*    

期望输出：30秒后的同步报文，`StuInfo.txt`

>测试结果  ：**正确**    

输入：`sync_session`  
   
*来自另一校区的学生，学号 505~606*  
  

期望输出：30秒后的同步报文，`StuInfo.txt`

>测试结果  ：**正确**    

输入：`add_session`  
  
*修改学号为11的学生的名字为`test`*  
  
期望输出：`ack`，30秒后的同步报文 ，`StuInfo.txt ` 

>测试结果  ：**正确**    

***
Copyright Reserved.