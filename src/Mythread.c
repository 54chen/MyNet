#include <gnome.h>
#include <sys/select.h>
#include "Mythread.h"
#include "connect.h"
#include "support.h"
#include "interface.h"

int i=0;
typedef struct{
                  long    tv_sec;         
                  long    tv_uec;        
              }timeval;
			  
gint
keeplink(gpointer data)
{
pthread_t keeptest;
	fd_set readfds;
	timeval timeout={5,0};//设置超时
	BYTE recvbuf[1024];
	BYTE cmd;
	CMD_RECORD *cmd_record;
	int recvlen;
	int index=0;
	BYTE tmp=0;
	send_keeplink_request();
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);
	if(1!=select(sockfd + 1,&readfds,NULL,NULL,&timeout))
	{//超时
		Acc_Keep_Link=2;
		g_message("1.keep lost,thread keeptest ok!");
		pthread_create(&keeptest,NULL,Keep_Thread,NULL);
		return FALSE;
	}
	recvlen=recvfrom(sockfd,(char *)recvbuf,sizeof(recvbuf),0,NULL,NULL);
	if (recvlen==-1 ) {
					Acc_Keep_Link=2;
					pthread_create(&keeptest,NULL,Keep_Thread,NULL);
					g_message("2.keep lost,thread keeptest ok!");
					return FALSE;
	}
	amt_decrypt(recvbuf,recvlen);
	if(0==check_packet(recvbuf,recvlen))
	{
					Acc_Keep_Link=2;
					pthread_create(&keeptest,NULL,Keep_Thread,NULL);
					g_message("3.keep lost,thread keeptest ok!");
					return FALSE;
	}
	cmd_record=get_attr(recvbuf);
	cmd=*recvbuf;
	if(cmd==4)    //收到send_keeplink_request对应的包
	{
		index=0;
		tmp=0;
		for (;(index<8)&&(attr_id[index]);index++) {
			if (attr_id[index]==3) {
				if (attr_val[8*(index+4*index)]!=1) {//发送send_keeplink_request失败
					Acc_Keep_Link=2;
					pthread_create(&keeptest,NULL,Keep_Thread,NULL);
					g_message("4.keep lost,thread keeptest ok!");
					return FALSE;
				}
			}
		}
		//AfxGetMainWnd()->PostMessage(WM_KEEPLINK_RESULT,KEEPLINK_SUCCESSED,NULL);
		g_message("keeplink result success");
	}
	else
	{
					Acc_Keep_Link=2;
					pthread_create(&keeptest,NULL,Keep_Thread,NULL);
					g_message("5.keep lost,thread keeptest ok!");
					return FALSE;
	}
return TRUE;
}

void 
Link_Thread(void *arg)
{
guint send_timer;
if(Acc_Keep_Link!=1)return;
g_message("keep thread online!");
send_timer=gtk_timeout_add(30000,keeplink,NULL);
}

void
Access_Thread()
{
if(Acc_Keep_Link!=0)return;
pthread_t keeplink;
int times=0;//超时次数
fd_set readfds;
timeval timeout;//设置超时为5秒
timeout.tv_sec=5;
timeout.tv_uec=0;
FD_ZERO(&readfds);
FD_SET(sockfd, &readfds);	

BYTE recvbuf[1024];
BYTE cmd;
CMD_RECORD *cmd_record;
int recvlen;
int index=0;
BYTE tmp=0;

	
retry:
		if (times>=2) {
		Acc_Keep_Link=-1;//ACCESS_FAILED_TIMEOUT;
		return ;
	}
send_access_request();

int rt=select(sockfd + 1,&readfds,NULL,NULL,&timeout);
//g_message("select id :%d",rt);
if(1!=rt)
	{//超时
		g_message("time out this");
		times++;
		goto retry;
	}

recvlen=recvfrom(sockfd,(char *)recvbuf,sizeof(recvbuf),0,NULL,NULL);
	if (recvlen==-1) {
		g_message("recvfrom faild");
		
	}
	amt_decrypt(recvbuf,recvlen);
	if(check_packet(recvbuf,recvlen)==0&&times<2)
	{   g_message("check_packet bad here");
		times++;
		goto retry;//check_packet失败则重发数据包
	}
	cmd_record=get_attr(recvbuf);
	cmd=*recvbuf;
	if(cmd==2)    //收到send_access_request对应的包
	{
		get_spec_attr(cmd_record);
		index=0;
		tmp=0;
		
		for (;(index<0x0A)&&(attr_id[index]!=0);index++) {
			
			if (attr_id[index]==3) {
				tmp=attr_val[8*(index+4*index)];////attr_val给每个命令40字节
			}
		}
		if (tmp==1) {
	        //g_message("ok");
			gtk_widget_hide_all (linkwindow);
			Acc_Keep_Link=1;
			pthread_create(&keeplink,NULL,Link_Thread,NULL);
			return;
		}
		else
		{   g_message("server_back_err");
			gtk_widget_hide_all (linkwindow);
			Acc_Keep_Link=-1;
			return ;
		}

	}

}


gint
keeptest(gpointer data)
{
pthread_t keeplink;
i++;
g_message("%d",i);
if (i>10){Acc_Keep_Link=-1;g_message("can't keeplink!");return FALSE;}
	fd_set readfds;
	timeval timeout={5,0};//设置超时
	BYTE recvbuf[1024];
	BYTE cmd;
	CMD_RECORD *cmd_record;
	int recvlen;
	int index=0;
	BYTE tmp=0;
	send_keeplink_request();
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);
	if(1!=select(sockfd + 1,&readfds,NULL,NULL,&timeout))
	{//超时
		g_message("1.keep lost,thread keeptest for once!");
		return TRUE;
	}
	recvlen=recvfrom(sockfd,(char *)recvbuf,sizeof(recvbuf),0,NULL,NULL);
	if (recvlen==-1 ) {
					g_message("2.keep lost,thread keeptest for once!");
					return TRUE;
	}
	amt_decrypt(recvbuf,recvlen);
	if(0==check_packet(recvbuf,recvlen))
	{
					g_message("3.keep lost,thread keeptest for once!");
					return TRUE;
	}
	cmd_record=get_attr(recvbuf);
	cmd=*recvbuf;
	if(cmd==4)    //收到send_keeplink_request对应的包
	{
		index=0;
		tmp=0;
		for (;(index<8)&&(attr_id[index]);index++) {
			if (attr_id[index]==3) {
				if (attr_val[8*(index+4*index)]!=1) {//发送send_keeplink_request失败
					g_message("4.keep lost,thread keeptest for once!");
					return TRUE;
				}
			}
		}
			g_message("keeptest result success");
		    Acc_Keep_Link=1;
			pthread_create(&keeplink,NULL,Link_Thread,NULL);
			return FALSE;		
	}
	else
	{
					g_message("5.keep lost,thread keeptest for once!");
					return TRUE;
	}

return FALSE;
}

void
Keep_Thread()
{guint send_timer;
	if(Acc_Keep_Link!=2)return;
	send_timer=gtk_timeout_add(10000,keeptest,NULL);
}
