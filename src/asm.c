#include "stdafx.h"
#include "md5.h"
#include "global.h"
#include <string.h>


//本源文件为从upnet,downnet反汇编后得到的全局变量和函数

BYTE username[0x40]={0,};
BYTE host[0x1E]={0,};
BYTE mac_addr[0x20]={0,};
BYTE ip_addr[0x20]={0,};
//DWORD findservice;
SOCKADDR_IN client;//服务器端的地址
BYTE randnum[0x28]={0,};
BYTE passwd[0x40]={0,};
BYTE server_type[0x40]={0,};
SOCKET sockfd,socketleave;

BYTE attr_id[0x0a]={0,};
BYTE attr_len[0x0a]={0,};
BYTE attr_val[0x190]={0,};

void md5_calc(BYTE * md5_digest,BYTE * inputbuf,int inputlen)
//md5_digest存储消息摘要，至少16字节，本函数没有校验参数
{
	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context, inputbuf, inputlen);
	MD5Final(md5_digest, &context);

}

int amt_crypt(BYTE * inputbuf,int inputlen)
//原程序中的加密算法,要发送的数据包经过md5算出消息摘要后一起经本函数加密后发送
//返回0表示运算结束，1则参数有错
{
	int index;
	BYTE tmp;
	if ((inputlen<=0)||(inputbuf==NULL)) return 1;
	for (index=0;index<inputlen;index++) {
		tmp=inputbuf[index];
		__asm
		{
				mov     cl, tmp
				mov     dl, cl
				shl     edx, 7
				mov     al, cl
				and     eax, 2
				shr     al, 1
				or      edx, eax
				mov     al, cl
				and     eax, 4
				shl     eax, 2
				or      edx, eax
				mov     al, cl
				and     eax, 8
				shl     eax, 2
				or      edx, eax
				mov     al, cl
				and     eax, 10h
				shl     eax, 2
				or      edx, eax
				mov     al, cl
				and     eax, 20h
				shr     al, 2
				or      edx, eax
				mov     al, cl
				and     eax, 40h
				shr     al, 4
				or      edx, eax
				and     ecx, 80h
				shr     cl, 6
				or      edx, ecx
				mov     tmp, dl
		}
		inputbuf[index]=tmp;
	}
	return 0;
}

int amt_decrypt(BYTE * inputbuf,int inputlen)
//原程序中的解密算法,接收到的数据包得经过本函数解密
//返回0表示运算结束，1则参数有错
{
	int index;
	BYTE tmp;
	if ((inputlen<=0)||(inputbuf==NULL)) return 1;
	for (index=0;index<inputlen;index++) {
		tmp=inputbuf[index];
		__asm
		{
				mov     cl, tmp
				mov     dl, cl
				and     edx, 1
				shl     edx, 1
				mov     al, cl
				and     eax, 2
				shl     eax, 6
				or      edx, eax
				mov     al, cl
				and     eax, 4
				shl     eax, 4
				or      edx, eax
				mov     al, cl
				and     eax, 8
				shl     eax, 2
				or      edx, eax
				mov     al, cl
				and     eax, 10h
				shr     al, 2
				or      edx, eax
				mov     al, cl
				and     eax, 20h
				shr     al, 2
				or      edx, eax
				mov     al, cl
				and     eax, 40h
				shr     al, 2
				or      edx, eax
				shr     cl, 7
				or      edx, ecx
				mov     tmp, dl

		}
		inputbuf[index]=tmp;
	}
	return 0;
}



//void send_request_cmd(int cmd)
//cmd表示请求类型,1 send_access_request,3 sendkeeplinkrequest, 7 send_service_request
/*{
	if(cmd==1){
		send_access_request();
	}
	else if (cmd==3) {
		sendkeeplinkrequest();
	}
	else if (cmd==7) {
		send_service_request();
	}
	else
		return;

}*/


int send_service_request()//返回1成功，0失败，返回值我自己定义的
{
	BYTE sendbuf[0x1A];
	BYTE md5_digest[16];
	memset(sendbuf,0,sizeof(sendbuf));
	//下面构造发送数据包
	sendbuf[0]=7;					//sendbuf第一个字节为命令，7表示请求服务类型
	sendbuf[18]=7;
	sendbuf[19]=8;
	memcpy(sendbuf+20,mac_addr,6);//6字节mac地址
	sendbuf[1]=0x1A;				//sendbuf第2个字节为总buf长度，从第3字节开始共16字节为MD5消息摘要
	md5_calc(md5_digest,sendbuf,0x1A);
	memcpy(sendbuf+2,md5_digest,16);//填入消息摘要
	amt_crypt(sendbuf,0x1A);

	int rt;
	rt=sendto(sockfd,(char *)sendbuf,0x1A,0,(SOCKADDR *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==SOCKET_ERROR)||(rt!=0x1A)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功
}

int send_access_request()//返回1成功，0失败，返回值我自己定义的
{
	BYTE sendbuf[500];//应该足够？？？？？！！！！！
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
	TRACE("%d %d %d %d",usernamelen,passwdlen,ip_addrlen,server_typelen);

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
	memcpy(sendbuf+20+usernamelen+1+1+passwdlen+1+1,mac_addr,6);//6字节mac地址
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

	int rt;
	rt=sendto(sockfd,(char *)sendbuf,sendbuflen,0,(SOCKADDR *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==SOCKET_ERROR)||(rt!=sendbuflen)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功

}

int send_keeplink_request()//返回1成功，0失败，返回值我自己定义的
{
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
	memcpy(sendbuf+20,mac_addr,6);//6 bytes mac address
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
	rt=sendto(sockfd,(char *)sendbuf,sendbuflen,0,(SOCKADDR *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==SOCKET_ERROR)||(rt!=sendbuflen)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功
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
	memcpy(sendbuf+20,mac_addr,6);
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
	rt=sendto(socketleave,(char *)sendbuf,sendbuflen,0,(SOCKADDR *)&client,0x10);//0x10用sizeof(client)代替？？？！！！！！
	if ((rt==SOCKET_ERROR)||(rt!=sendbuflen)) {
		return 0;//发送失败
	}
	else
		return 1;//发送成功
}

int check_packet(BYTE * recvbuf,int recvlen)//检查解密amt_decrypt完后的数据包，返回0失败，1成功
{
	BYTE recv_md5_digest[16];
	BYTE md5_digest[16];
	if (recvlen<(int)(*(recvbuf+1))) {
		//AfxMessageBox("接收到的包长度不等");
		return 0;
	}
	if ((*(recvbuf+1))<=0x11) {
		return 0;
	}
	memcpy(recv_md5_digest,recvbuf+2,sizeof(recv_md5_digest));
	memset(recvbuf+2,0,sizeof(recv_md5_digest));
	md5_calc(md5_digest,recvbuf,(int)(*(recvbuf+1)));
	if(0!=memcmp(md5_digest,recv_md5_digest,sizeof(recv_md5_digest)))
	{
		//AfxMessageBox("接收到的包MD5摘要不等");
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


/*int handle_packet(BYTE * recvbuf,int recvbuflen)  //这里是从linux版反汇编出来，直接在程序对话框类实现文件里写吧
{
	BYTE cmd;
	check_packet(recvbuf,recvbuflen);//如果失败在本函数里有MessageBox，还要做别的处理？？？？
	CMD_RECORD *cmd_record=get_attr(recvbuf);
	cmd=*recvbuf;
	switch(cmd) {
	case 2:    //收到send_access_request对应的包
		get_spec_attr(cmd_record);
		int index=0;
		BYTE tmp=0;
		for (;(index<0x0A)&&(attr_id[index]!=0);index++) {
			if (attr_id[index]==3) {
				tmp=attr_val[8*(index+4*index)];////attr_val给每个命令40字节
			}
		}
			if (tmp==1) {
				AfxMessageBox("认证成功");
			}
			else
			{
				AfxMessageBox("认证失败");
			}



			break;
	case 4:		//收到send_keeplink_request对应的包
		int index=0;
		BYTE tmp=0;
		for (;(index<8)&&(attr_id[index]);index++) {
		if (attr_id[index]==3) {
			if (attr_val[8*(index+4*index)]!=1) {//发送send_keeplink_request失败
				AfxMessageBox("send_keeplink_request后，接收到得数据表明失败");
				ExitProcess(0);
			}
		}
		}
		//到这表明send_keeplink_request后收到的数据表明成功，继续

		break;
	case 6:		//收到send_leave_request对应的包
		AfxMessageBox("下线成功");
		ExitProcess(0);
		break;
	case 8:		//收到send_service_request对应的包
		//我这里没有处理收到的数据包，直接当成"internet"，然后存在注册表里，可能还需要修改？？？？！！！！！
		//AfxMessageBox("获取服务成功");
		//AfxGetApp()->WriteProfileString("Setting","ServiceName","internet",strlen("internet"));
		break;
	default:	//unknow cmd
	}
}*/
