#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <gnome.h>
#include "Mythread.h"
#include "connect.h"
#include "callbacks.h"
#include "interface.h"
#include "support.h" 

gchar line2[255];//用来存去掉回车后的字符串
void write_config(gchar *usr,gchar *pwd);//remember pwd
void write_new_config();//first time to write config
gchar * scape(gchar *line);//escapse the enter like '\n'
char *get_mac();//return the mac address
char *get_ip();//get ip address
int get_socket();  
int tr_mac();//translate the mac address
int CreateMutex();//a file like mutex
int trayshow;


void
on_window1_show                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
/*
char runfile[1024]="";
FILE *runfp;	
sprintf(runfile,"%s/.mynet/run.pid",getenv("HOME"));

if((runfp = fopen(runfile, "r")) != NULL)
	{    
    gtk_widget_hide(window1);
	getAtrBox = create_messagebox("错误","程序已经运行了！",0);
 	gtk_widget_show (getAtrBox);
	}else{
		CreateMutex();
		}
*/
username[0x40]=0;
host[0x1E]=0;
memcpy(host,SERVER,strlen((char *)SERVER));
mac_addr[0x20]=0;
mac_Hex[6]=0;
ip_addr[0x20]=0;
passwd[0x40]=0;
server_type[0x40]=0;
memcpy(server_type,"internet",strlen((char *)"internet"));

gchar *line = ((char *) malloc(255));//is 255b enough? 
char cfgfile[1024]="";
FILE *fp;	
	
sprintf(cfgfile,"%s/.mynet/config",getenv("HOME"));
if ((fp = fopen(cfgfile, "r")) == NULL)	write_new_config();
else 
	{
	fgets(line,254,fp);
	gtk_entry_set_text ((GtkEntry *)entry1,(const gchar *)scape(line));
	memcpy(username,scape(line),strlen(scape(line)));
	fgets(line,254,fp);
	gtk_entry_set_text ((GtkEntry *)entry2,(const gchar *)scape(line));	
	memcpy(passwd,scape(line),strlen(scape(line)));
	fgets(line,254,fp);
	memcpy(ip_addr,scape(line),strlen(scape(line)));
	fgets(line,254,fp); 
	memcpy(host,scape(line),strlen(scape(line)));g_message("here1");
	//get_socket((char *)scape(line));//host to 
		g_message("%c",&line);
	fgets(line,254,fp);g_message("here3");
	memcpy(mac_addr,scape(line),strlen(scape(line)));g_message("here4");
	tr_mac();g_message("here5");
	}	
g_message("mem now here:usr:%s\npwd:%s\nip:%s\nmac:%s\nserver:%s",username,passwd,ip_addr,mac_addr,host);
free(line);
}


void
on_window2_show                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
	gtk_entry_set_text ((GtkEntry *)entry3,(char *)ip_addr);

	gtk_entry_set_text ((GtkEntry *)entry4,(char *)host);	

	gtk_combo_box_append_text (GTK_COMBO_BOX (comboboxentry1),(char *)mac_addr);
	gtk_combo_box_set_active(GTK_COMBO_BOX (comboboxentry1),0);
	
}

void
on_button3_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
    GtkWidget *mac_set;
	mac_set = create_window2 ();
 	gtk_widget_show (mac_set);
	return;
}

gint
flash_timeout(gpointer data)
{if(Acc_Keep_Link==-1){
	gtk_widget_hide_all (linkwindow);
	gtk_widget_show_all (window1);
	getAtrBox = create_messagebox("提示","与网络连接中断！",1);
 	gtk_widget_show_all (getAtrBox);
	return FALSE;
	}
	create_tray(tray);
	return TRUE;
}

void
on_button1_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{	
if(gtk_toggle_button_get_active((GtkToggleButton *)checkbutton1))
write_config((gchar *)gtk_entry_get_text ((GtkEntry *)entry1),
			(gchar *)gtk_entry_get_text ((GtkEntry *)entry2));
else
write_config((gchar *)gtk_entry_get_text ((GtkEntry *)entry1),
			"");	
gtk_widget_hide_all (window1);
linkwindow = create_window3 ();
gtk_widget_show_all (linkwindow);
gint ptimer_flash=0;
gtk_timeout_remove(ptimer_flash);
ptimer_flash=gtk_timeout_add(15000,flash_timeout,NULL);	
	
pthread_t getaccess;
Acc_Keep_Link=0;
memcpy(username,(char *)gtk_entry_get_text ((GtkEntry *)entry1),strlen((char *)gtk_entry_get_text ((GtkEntry *)entry1)));
memcpy(passwd,(char *)gtk_entry_get_text ((GtkEntry *)entry2),strlen((char *)gtk_entry_get_text ((GtkEntry *)entry2)));
pthread_create(&getaccess,NULL,Access_Thread,NULL);
}

void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{  
memcpy(host,(char *)gtk_entry_get_text ((GtkEntry *)entry4),strlen((gchar *)gtk_entry_get_text ((GtkEntry *)entry4)));
write_config((gchar *)gtk_entry_get_text ((GtkEntry *)entry1),
			"");

	get_socket((char *)gtk_entry_get_text ((GtkEntry *)entry4));
	getAtrBox = create_messagebox("提示","恭喜，获取服务成功！",1);
 	gtk_widget_show (getAtrBox);
	return;//sorry i can not understand what is this
}

void
before_quit                      (GtkWidget       *widget,
                                        gpointer         user_data)
{
/*
char cfgfile[1024]="";
sprintf(cfgfile,"%s/.mynet/run.pid",getenv("HOME"));
unlink(cfgfile);//delete mutex file*/
	
if(gtk_toggle_button_get_active((GtkToggleButton *)checkbutton1))
write_config((gchar *)gtk_entry_get_text ((GtkEntry *)entry1),
			(gchar *)gtk_entry_get_text ((GtkEntry *)entry2));//remember the passwd
close(sockfd); 
gtk_main_quit();
}


void write_new_config()
{
int log;
char filename[1024];
char log_string[1024];
char filepath[1024];
char *dir;
strcpy(log_string,"");
strcat(log_string,"\n");memcpy(username,"0",strlen((char *)username));
strcat(log_string,"\n");memcpy(passwd,"0",strlen((char *)passwd));
get_ip();	
strcat(log_string,(char *)ip_addr);strcat(log_string,"\n");
strcat(log_string,SERVER);strcat(log_string,"\n");
get_mac();tr_mac();
strcat(log_string,(char *)mac_addr);strcat(log_string,"\n");
dir=getenv("HOME");
sprintf(filepath,"%s/.mynet/",dir);
mkdir(filepath,O_RDWR|O_CREAT|O_TRUNC);
chmod(filepath,0777);
sprintf(filename,"%sconfig",filepath);
log=open(filename,O_RDWR|O_CREAT|O_TRUNC,0777);
chmod(filename,0777);
write(log,log_string,strlen(log_string));
close(log);	
}

gchar * scape(gchar *line)
{
 int i;
 int j;
for(i=0;i<254;i++)line2[i]=NULL;
for(i=0;i<254;i++){if((line[i]=='\n')||(line[i]=='\r'))break;}	
for(j=0;j<i;j++){line2[j]=line[j];/*g_message("%c",line[j]);*/}
return line2;
}


void write_config( gchar* usr, gchar* pwd)
{
int log;
char filename[1024];
char log_string[1024];
char filepath[1024];

strcpy(log_string,"");
strcat(log_string,usr);strcat(log_string,"\n");
strcat(log_string,pwd);strcat(log_string,"\n");
strcat(log_string,(char *)ip_addr);strcat(log_string,"\n");
strcat(log_string,(char *)host);strcat(log_string,"\n");
strcat(log_string,(char *)mac_addr);strcat(log_string,"\n");

sprintf(filepath,"%s/.mynet/",getenv("HOME"));
mkdir(filepath,O_RDWR|O_CREAT|O_TRUNC);
chmod(filepath,0777);
sprintf(filename,"%sconfig",filepath);
log=open(filename,O_RDWR|O_CREAT|O_TRUNC,0777);
chmod(filename,0777);
write(log,log_string,strlen(log_string));
close(log);	
} 

void
delete_event                     (GtkButton       *button,
                                        gpointer         user_data)
{
before_quit((GtkWidget *)button,(gpointer)user_data);
}

char *
get_mac()
{
        int nSocket;
        struct ifreq struReq;
        nSocket = socket(PF_INET,SOCK_STREAM,0);
        memset(&struReq,0,sizeof(struReq));
        strncpy(struReq.ifr_name, "eth0", sizeof(struReq.ifr_name));   
        ioctl(nSocket,SIOCGIFHWADDR,&struReq);
        close(nSocket);
		//strcpy(mac_addr,(BYTE)ether_ntoa(struReq.ifr_hwaddr.sa_data));
		memcpy(mac_addr,(char *)ether_ntoa(struReq.ifr_hwaddr.sa_data),strlen((char *)ether_ntoa(struReq.ifr_hwaddr.sa_data)));
		//g_message("\n get_mac: %s\n",(char *)ether_ntoa(struReq.ifr_hwaddr.sa_data)+1);
		//g_message("\n mem_mac : %s  lenth:%d\n",mac_addr,strlen((char *)mac_addr));
		return 0;
}

char *  
get_ip()  
  {  
	       int  sock;  
           struct  sockaddr_in  sin;  
           struct  ifreq  ifr;   
           sock  =  socket(AF_INET,  SOCK_DGRAM,  0);  
           if  (sock  ==  -1)  
           {  
                       perror("socket");  
                       return  "";                          
           }  
             
           strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name));       
    
           if  (ioctl(sock,  SIOCGIFADDR,  &ifr)  <  0)  
           {  
                       perror("ioctl");  
                       return  "";  
           }  
 
           memcpy(&sin,  &ifr.ifr_addr,  sizeof(sin));   
           close(sock);  
		   memcpy(ip_addr,inet_ntoa(sin.sin_addr),strlen(inet_ntoa(sin.sin_addr)));
           //g_message("\n get_ip:eth0:  %s\n",inet_ntoa(sin.sin_addr)); 
		   //g_message("\n mem_ip: %s",ip_addr);
		   return  ""; 
}

int  
get_socket()  
  { char *ser;
	ser=(gchar *)gtk_entry_get_text ((GtkEntry *)entry4);
	//digtalser
           sockfd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
           if  (sockfd  ==  -1)  
           {  
                       perror("socket");  
                       return  0;                          
           }  
		   client.sin_family=AF_INET;
	       client.sin_port=htons(3848); 
		   //client.sin_addr=inet_addr(host);	
		   inet_pton(AF_INET, ser, &client.sin_addr);  		   
           //g_message("udp socket ok!%d",sockfd); 
           return  1; 
}
int
chToHex(int x)//字符转成十六进制用
{
if(x>=97&&x<=102)x=x-87;
else x=x-48;
return x;
}
int
tr_mac()
{
 int p,i;

 p=0;
 for(i=0;i<6;i++)
	 {
	  if (mac_addr[p+1]==':'){mac_Hex[i]=chToHex((int)mac_addr[p]);p+=2;}
      else{mac_Hex[i]=16*(chToHex((int)mac_addr[p]))+chToHex((char)mac_addr[p+1]);p+=3;}	  
	 }
//g_message("%s",mac_addr);
//for(i=0;i<6;i++)
//g_message("%d---%c-%c-%c-%c",mac_Hex[i],mac_addr[i],mac_addr[i+1],mac_addr[i+2],mac_addr[i+3]);
return 0;
}

int 
CreateMutex()//a file like mutex
{
int log;
char filename[1024];
char log_string[1024];
char filepath[1024];
char *dir;
strcpy(log_string,"MyNet");
dir=getenv("HOME");
sprintf(filepath,"%s/.mynet/",dir);
mkdir(filepath,O_RDWR|O_CREAT|O_TRUNC);
chmod(filepath,0777);
sprintf(filename,"%srun.pid",filepath);
log=open(filename,O_RDWR|O_CREAT|O_TRUNC,0777);
chmod(filename,0777);
write(log,log_string,strlen(log_string));
close(log);	
return 1;	
}

void 
delete_getAtrBox()
{
gtk_widget_hide (getAtrBox);
}
