#include "connect.h"
#include <ctype.h>



int send_service_request()//返回1成功，0失败，返回值我自己定义的
{
	BYTE sendbuf[0x1A];
	BYTE md5_digest[16];
	memset(sendbuf,0,sizeof(sendbuf));
	//下面构造发送数据包
	sendbuf[0]=7;					//sendbuf第一个字节为命令，7表示请求服务类型
	sendbuf[18]=7;
	sendbuf[19]=8;
	memcpy(sendbuf+20,mac_Hex,6);//6字节mac地址
	//g_message("%s",mac_addr);
	sendbuf[1]=0x1A;				//sendbuf第2个字节为总buf长度，从第3字节开始共16字节为MD5消息摘要
	md5_calc(md5_digest,sendbuf,0x1A);
	memcpy(sendbuf+2,md5_digest,16);//填入消息摘要
	g_message("\nmd5 :\n%s",sendbuf+2);
	amt_crypt(sendbuf,0x1A);
	int rt;
    //sendto(sockfd, mesg, n, 0, pcliaddr, len);
	rt=sendto(sockfd,(char *)sendbuf,0x1A,0,(struct sockaddr *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==-1)||(rt!=0x1A)) {
		g_message("send service fail");
		return 0;//发送失败
	}
	else
		return 1;//发送成功
}

int send_access_request()//返回1成功，0失败，返回值我自己定义的
{
	BYTE sendbuf[1024];//应该足够？？？？？！！！！！
	BYTE md5_digest[16];
	int usernamelen;
	int passwdlen;
	int ip_addrlen;
	int server_typelen;
	int sendbuflen;

	usernamelen=(int)strlen((char *)username);
	passwdlen=(int)strlen((char *)passwd);
	ip_addrlen=(int)strlen((char *)ip_addr);
	server_typelen=(int)strlen((char *)server_type);
	

	memset(sendbuf,0,sizeof(sendbuf));
	//下面构造发送数据包
	sendbuf[0]=1;
	sendbuf[18]=1;
	sendbuf[19]=usernamelen+2;
	memcpy(sendbuf+20,username,usernamelen);
	sendbuf[20+usernamelen]=2;
	sendbuf[20+usernamelen+1]=passwdlen+2;
	memcpy(sendbuf+20+usernamelen+1+1,passwd,passwdlen);
	sendbuf[20+usernamelen+1+1+passwdlen]=7;
	sendbuf[20+usernamelen+1+1+passwdlen+1]=8;
	memcpy(sendbuf+20+usernamelen+1+1+passwdlen+1+1,mac_Hex,6);//6字节mac地址
	sendbuf[20+usernamelen+1+1+passwdlen+1+1+6]=9;
	sendbuf[20+usernamelen+1+1+passwdlen+1+1+6+1]=ip_addrlen+2;
	memcpy(sendbuf+20+usernamelen+1+1+passwdlen+1+1+6+1+1,ip_addr,ip_addrlen);
	sendbuf[20+usernamelen+1+1+passwdlen+1+1+6+1+1+ip_addrlen]=0x0A;
	sendbuf[20+usernamelen+1+1+passwdlen+1+1+6+1+1+ip_addrlen+1]=server_typelen+2;
	memcpy(sendbuf+20+usernamelen+1+1+passwdlen+1+1+6+1+1+ip_addrlen+1+1,server_type,server_typelen);
	sendbuflen=20+usernamelen+1+1+passwdlen+1+1+6+1+1+ip_addrlen+1+1+server_typelen;
	sendbuf[1]=sendbuflen;//sendbuf第2字节为总长度
	md5_calc(md5_digest,sendbuf,sendbuflen);
	memcpy(sendbuf+2,md5_digest,16);//填入消息摘要
	amt_crypt(sendbuf,sendbuflen);
//    g_message("usernamelen:%d\npasswdlen:%d\nip_addrlen:%d\nserver_typelen:%d\ntotallen:%d",usernamelen,passwdlen,ip_addrlen,server_typelen,sendbuflen);
	int rt;
	rt=sendto(sockfd,(char *)sendbuf,sendbuflen,0,(struct sockaddr *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==-1)||(rt!=sendbuflen)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功
}

int send_keeplink_request()//返回1成功，0失败，返回值我自己定义的
{ //g_message("send keeplink page");
	BYTE sendbuf[500];//应该足够？？？？？！！！！！
	BYTE md5_digest[16];
	int ip_addrlen=(int)strlen((char *)ip_addr);
	int randnumlen=(int)strlen((char*)randnum);
	int sendbuflen;

	memset(sendbuf,0,sizeof(sendbuf));
	//下面构造发送数据包
	sendbuf[0]=3;//cmd 3 表示send_keeplink_request
	sendbuf[18]=7;
	sendbuf[19]=8;
	memcpy(sendbuf+20,mac_Hex,6);//6 bytes mac address
	sendbuf[20+6]=8;
	sendbuf[20+6+1]=randnumlen+2;
	memcpy(sendbuf+20+6+1+1,randnum,randnumlen);
	sendbuf[20+6+1+1+randnumlen]=9;
	sendbuf[20+6+1+1+randnumlen+1]=ip_addrlen+2;
	memcpy(sendbuf+20+6+1+1+randnumlen+1+1,ip_addr,ip_addrlen);
	sendbuflen=20+6+1+1+randnumlen+1+1+ip_addrlen;
	sendbuf[1]=sendbuflen;
	md5_calc(md5_digest,sendbuf,sendbuflen);
	memcpy(sendbuf+2,md5_digest,16);//填入消息摘要
	amt_crypt(sendbuf,sendbuflen);

	int rt;
	rt=sendto(sockfd,(char *)sendbuf,sendbuflen,0,(struct sockaddr *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==-1)||(rt!=sendbuflen)) {
		g_message("send fail");
		//return 0;//发送失败
	}
	else g_message("send success");
		//return 1;//发送成功
}

int send_leave_request()//返回1成功，0失败，返回值我自己定义的
{
	BYTE sendbuf[500];//应该足够？？？？？！！！！！
	BYTE md5_digest[16];
	int ip_addrlen=(int)strlen((char *)ip_addr);
	int randnumlen=(int)strlen((char *)randnum);
	int sendbuflen;

	
	memset(sendbuf,0,sizeof(sendbuf));
	//下面构造发送数据包
	sendbuf[0]=5;//cmd 5 表示send_leave_request
	sendbuf[18]=7;
	sendbuf[19]=8;
	memcpy(sendbuf+20,mac_Hex,6);
	sendbuf[20+6]=8;
	sendbuf[20+6+1]=randnumlen+2;
	memcpy(sendbuf+20+6+1+1,randnum,randnumlen);
	sendbuf[20+6+1+1+randnumlen]=9;
	sendbuf[20+6+1+1+randnumlen+1]=ip_addrlen+2;
	memcpy(sendbuf+20+6+1+1+randnumlen+1+1,ip_addr,ip_addrlen);
	sendbuflen=20+6+1+1+randnumlen+1+1+ip_addrlen;
	sendbuf[1]=sendbuflen;
	md5_calc(md5_digest,sendbuf,sendbuflen);
	memcpy(sendbuf+2,md5_digest,16);//填入消息摘要
	amt_crypt(sendbuf,sendbuflen);

	int rt;
	rt=sendto(socketleave,(char *)sendbuf,sendbuflen,0,(struct sockaddr *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	//rt=sendto(socketleave,(char *)sendbuf,sendbuflen,0,(SOCKADDR *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==-1)||(rt!=sendbuflen)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功
}

int check_packet(BYTE * recvbuf,int recvlen)//检查解密amt_decrypt完后的数据包，返回0失败，1成功
{ //g_message("here is the check_packet start!");
	BYTE recv_md5_digest[16];
	BYTE md5_digest[16];
	if (recvlen<(int)(*(recvbuf+1))) {
		g_message("leth haven't ok");
		return 0;
	}
	if ((*(recvbuf+1))<=0x11) {
		g_message("len2 0x11 haven't ok");
		return 0;
	}
	memcpy(recv_md5_digest,recvbuf+2,sizeof(recv_md5_digest));
	memset(recvbuf+2,0,sizeof(recv_md5_digest));
	md5_calc(md5_digest,recvbuf,(int)(*(recvbuf+1)));
	if(0!=memcmp(md5_digest,recv_md5_digest,sizeof(recv_md5_digest)))
	{
		g_message("MD5 haven't ok!");
		return 0;

	}
	return 1;

}

CMD_RECORD * get_attr(BYTE * recvbuf)//返回NULL失败，成功时返回一个buffer
{
	BYTE * p=recvbuf;
	BYTE cmd,cmd_len_tol;//cmd_len_tol是cmd的buf长度加上2
	CMD_RECORD * rt;
	int packetlen;
	

	packetlen=(int)(*(recvbuf+1))-0x12;
	if (packetlen<0) {
		return NULL;
	}
	p+=0x12;//跳过前面的18字节  p对应反汇编里的esi
	rt=NULL;
	while (packetlen>0) {
		cmd=*p;
		p++;
		cmd_len_tol=*p;
		p++;
		packetlen-=2;
		CMD_RECORD *malloc_buf1;
		malloc_buf1=(CMD_RECORD*)malloc(sizeof(CMD_RECORD));
		memset(malloc_buf1,0,sizeof(CMD_RECORD));
		malloc_buf1->cmd=cmd;
		malloc_buf1->len=cmd_len_tol-2;
		BYTE * malloc_buf2=(BYTE *)malloc(cmd_len_tol);
		memset(malloc_buf2,0,cmd_len_tol);
		memcpy(malloc_buf2,p,cmd_len_tol-2);
		if (*p==0x0b) {
			malloc_buf2++;///???????????????????????????????????????????????
		}
		int i;
		if (cmd==8) {
			memset(randnum,0,sizeof(randnum));
			memcpy(malloc_buf2,p,cmd_len_tol);
			int tmp=cmd_len_tol;
			for (i=0;i<cmd_len_tol;i++) {
				if(isdigit((int)(malloc_buf2[i])))
					randnum[i]=malloc_buf2[i];
				tmp--;
				if (tmp==0) {
					break;

				}
			}
			randnum[i+1]=0;
		}

		malloc_buf1->cmd_buf=malloc_buf2;
		packetlen=packetlen-cmd_len_tol+2;
		p=p+cmd_len_tol-2;

		if (rt==NULL) {
			rt=malloc_buf1;
		}
		else
		{
			malloc_buf1->next=rt;
			rt=malloc_buf1;
		}

	}

	return rt;

}

void get_spec_attr(CMD_RECORD * cmd_record)
{
	int index=0;
	BYTE	cmd,cmd_len;//cmd_len =cmd_len_tol-2
	BYTE tmp;
	memset(attr_id,0,sizeof(attr_id));
	memset(attr_len,0,sizeof(attr_len));
	memset(attr_val,0,sizeof(attr_val));
	while(cmd_record){	//一个结构体莲表，有->Next的
		cmd=cmd_record->cmd;
		attr_id[index]=cmd;
		cmd_len=cmd_record->len;
		attr_len[index]=cmd_len;
		tmp=index+4*index;
		memcpy(attr_val+8*tmp,cmd_record->cmd_buf,cmd_len);//attr_val给每个命令40字节
		index++;
		cmd_record=cmd_record->next;

	}	

}
