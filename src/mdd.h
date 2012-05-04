/***************************************************************************
 *            mdd.h
 *
 *  Tue Oct 17 12:06:29 2006
 *  Copyright  2006  User
 *  Email
 ****************************************************************************/
#include "md6.h"

#include <gnome.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>       
#include  <sys/socket.h>   
#include  <netinet/in.h>  
#include  <net/if_arp.h>  
#include  <arpa/inet.h>

/*整个系统里的全局变量*/
int Acc_Keep_Link;//控制流程使用的，以防万一(-2 -1 0 1 2)
BYTE username[0x40];
BYTE host[0x1E];
BYTE mac_addr[0x20];
BYTE mac_Hex[6];
BYTE ip_addr[0x20];
struct sockaddr_in client;
BYTE randnum[0x28];
BYTE passwd[0x40];
BYTE server_type[0x40];
int sockfd,socketleave;
BYTE attr_id[0x0a];
BYTE attr_len[0x0a];
BYTE attr_val[0x190];
/*==================*/

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

/*加密和解密的函数*/
void md5_calc(BYTE * md5_digest,BYTE * inputbuf,int inputlen);
int amt_crypt(BYTE * inputbuf,int inputlen);
int amt_decrypt(BYTE * inputbuf,int inputlen);
