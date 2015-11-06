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
        FILE* fin;
        FILE* fout;

        mac_configure(){
		memset(dest_macs,0,sizeof(dest_macs));
		list_len=0;
		memset(local_mac,0,sizeof(local_mac));
	}
	int Judge(const char&c){
		if((c>='0')and(c<='9'))
                        return c-'0';
		if((c>='A')and(c<='F'))
                        return c-'A'+10;
		if((c>='a')and(c<='f'))
                        return c-'a'+10;
		return -1;
	}
	void reverge(const int&a){
		int A=a/16;int B=a%16;
		if((A>=0)and(A<=9))
                        fprintf(fout, "%c",'0'+A);
		if((A>=10)and(A<=15))
                        fprintf(fout, "%c",'A'+A-10);
		if((B>=0)and(B<=9))
                        fprintf(fout, "%c",'0'+B);
		if((B>=10)and(B<=15))
                        fprintf(fout, "%c",'A'+B-10);
	}
	mac_configure(const string&s){
		fin = fopen(s.c_str(),"r");
		char c;
                int accum=0;

		memset(dest_macs,0,sizeof(dest_macs));
		list_len=0;
		memset(local_mac,0,sizeof(local_mac));

		while((c=getc(fin))!=':'){};//local
		while(accum<12)
			if(Judge(c=getc(fin))!=-1){
				local_mac[accum/2]*=16;
				local_mac[accum/2]+=Judge(c);
				accum++;
			}
		while((c=getc(fin))!=':'){};//destination

		accum=0;
                string *Mac=new string;
		vector<string> dest;dest.clear();
		while((c=getc(fin))!=-1){
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
                fclose(fin);
	}
	void Write_mac(uint8_t*a){
		for(int i=0;i<=4;i++){
			reverge(a[i]);fprintf(fout, "-");
		}
		reverge(a[5]);fprintf(fout, "\n");
	}
	void Write(const string&s){
		fout = fopen(s.c_str(),"w+");

		fprintf(fout, "local mac : ");
                Write_mac(local_mac);
		fprintf(fout, "destination mac : ");
		Write_mac(dest_macs[0]);

		for(int i=1;i<list_len;i++){
			fprintf(fout, "                  ");
			Write_mac(dest_macs[i]);
		}
                fclose(fout);
	}
};

#endif
