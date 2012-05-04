#include "Winsock2.h"
//限制的IP，本程序只能在这个IP的机器上运行 每个不同，向我申请该程序时提供
//#define RESTRICT_IP "172.16.43.75" //"172.16.37.82"
#define RESTRICT_IP "10.10.131.83"
#define WM_SHOWTASK WM_USER+1
#define WM_ACCESS_REQUEST WM_USER+2
#define WM_LEAVENET_REQUEST WM_USER+3
#define WM_ACCESS_RESULT WM_USER+4

#define ACCESS_FAILED_TIMEOUT	2
#define ACCESS_FAILED	0
#define ACCESS_SUCCESSED 1
#define LEAVENET_FAILED	0
#define LEAVENET_SUCCESSED 1
#define WM_KEEPLINK_REQUEST WM_USER+5
#define WM_LEAVENET_RESULT WM_USER+6
#define	WM_KEEPLINK_RESULT	WM_USER+7
#define KEEPLINK_SUCCESSED 1
#define KEEPLINK_FAILED	0

#ifndef __CMD_RECORD_
#define __CMD_RECORD_
typedef struct CMD_RECORD {
	BYTE cmd;
	BYTE len;
	WORD dummy;
	BYTE * cmd_buf;
	struct CMD_RECORD * next;
}CMD_RECORD;  //12个字节  接收到数据包后转化成CMD_RECORD结构体链表
#endif

extern BYTE username[0x40];
extern BYTE host[0x1E];
extern  BYTE mac_addr[0x20];
extern  BYTE ip_addr[0x20];
//DWORD findservice;
extern  SOCKADDR_IN client;//服务器端的地址
extern  BYTE randnum[0x28];
extern  BYTE passwd[0x40];
extern BYTE server_type[0x40];
extern SOCKET sockfd,socketleave;

extern  BYTE attr_id[0x0a];
extern  BYTE attr_len[0x0a];
extern  BYTE attr_val[0x190];

void md5_calc(BYTE * md5_digest,BYTE * inputbuf,int inputlen);
int amt_crypt(BYTE * inputbuf,int inputlen);
int amt_decrypt(BYTE * inputbuf,int inputlen);
int send_service_request();
int send_access_request();
int send_keeplink_request();
int send_leave_request();
int check_packet(BYTE * recvbuf,int recvlen);
CMD_RECORD * get_attr(BYTE * recvbuf);
void get_spec_attr(CMD_RECORD * cmd_record);
//int handle_packet(BYTE * recvbuf,int recvbuflen);
