#ifndef MAC_CONFIGURE_H
#define MAC_CONFIGURE_H

#include<iostream>
#include<cstring>
#include<vector>
#include<algorithm>
#include<inttypes.h>

using namespace std;

struct mac_configure {
        uint8_t dest_macs[256][6];
        size_t  list_len;
        uint8_t local_mac[6];

        mac_configure(){
		memset(dest_macs,0,sizeof(dest_macs));
		list_len=0;
		memset(local_mac,0,sizeof(local_mac));
	}
	int Judge(const char&c){
		if((c>='0')and(c<='9'))return c-'0';
		if((c>='A')and(c<='F'))return c-'A'+10;
		if((c>='a')and(c<='f'))return c-'a'+10;
		return -1;
	}
	void reverge(const int&a){
		int A=a/16;int B=a%16;
		if((A>=0)and(A<=9))printf("%c",'0'+A);
		if((A>=10)and(A<=15))printf("%c",'A'+A-10);
		if((B>=0)and(B<=9))printf("%c",'0'+B);
		if((B>=10)and(B<=15))printf("%c",'A'+B-10);
	}
	mac_configure(const string&s){
		freopen(s.c_str(),"r",stdin);
		char c;
		memset(dest_macs,0,sizeof(dest_macs));
		list_len=0;
		memset(local_mac,0,sizeof(local_mac));
		while((c=getc(stdin))!=':'){};//loca 
		int accum=0;
		while(accum<12)
			if(Judge(c=getc(stdin))!=-1){
				local_mac[accum/2]*=16;
				local_mac[accum/2]+=Judge(c);
				accum++;
			}
		while((c=getc(stdin))!=':'){};//destination
		accum=0;string*Mac=new string;
		vector<string> dest;dest.clear();
		while((c=getc(stdin))!=-1){
			if(Judge(c)!=-1){
				*Mac+=Judge(c);
				accum++;
			}
			if(accum==12){
				dest.push_back(*Mac);
				accum=0;
				Mac=new string;
			}
		}
		delete Mac;
		sort(dest.begin(),dest.end());
		for(auto i=dest.begin();i!=dest.end();i++){
			for(int j=0;j<12;j++){
				dest_macs[list_len][j/2]*=16;
				dest_macs[list_len][j/2]+=(*i)[j];
			}
			list_len++;
		}
                fclose(stdin);
	}
	void Write_mac(uint8_t*a){
		for(int i=0;i<=4;i++){
			reverge(a[i]);printf("-");
		}
		reverge(a[5]);printf("\n");
	}
	void Write(const string&s){
		freopen(s.c_str(),"w+",stdout);
		printf("local mac : ");Write_mac(local_mac);
		printf("destination mac : ");
		Write_mac(dest_macs[0]);
		for(int i=1;i<list_len;i++){
			printf("                  ");
			Write_mac(dest_macs[i]);
		}
		fclose(stdout);
	}
};

#endif
