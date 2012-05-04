#include <pthread.h>
#include "mdd.h"



int send_access_request();
int send_service_request();
int send_keeplink_request();
int send_leave_request();

int check_packet();

CMD_RECORD * get_attr(BYTE * recvbuf);
void get_spec_attr(CMD_RECORD * cmd_record);
