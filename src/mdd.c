#include "mdd.h"

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
		__asm__(
		     "movb %1, %%cl;"
		     "movb %%cl, %%dl;"
			 "shl $7,%%edx;"
			 "movb %%cl,%%al;"
		     "and $2,%%eax;"
		     "shr $1,%%al;"
		     "or %%eax,%%edx;"
			"movb %%cl,%%al;"
		 	"and $4,%%eax;"
			"shl $2,%%eax;"
			"or %%eax,%%edx;"
			"movb %%cl,%%al;"
			"and $8,%%eax;"
			"shl $2,%%eax;"
			"or %%eax,%%edx;"
			"movb %%cl,%%al;"
			"and  $0x10,%%eax;"
			"shl   $2,%%eax;"
			"or  %%eax, %%edx;"
			"movb  %%cl,%%al;"
			"and   $0x20,%%eax;"
			"shr     $2,%%al;"
			"or      %%eax,%%edx;"
			"movb     %%cl,%%al;"
			"and     $0x40,%%eax;"
			"shr     $4,%%al;"
			"or      %%eax,%%edx;"
			"and     $0x80,%%ecx;"
			"shr     $6,%%cl;"
			"or      %%ecx,%%edx;"
             "movb %%dl, %0;"
             :"=r"(tmp)
		     :"r"(tmp)       
            :"%ecx","%edx");
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
		__asm__(
				"movb     %1,%%cl;"
				"movb     %%cl,%%dl;"
				"and     $1,%%edx;"
				"shl     $1,%%edx;"
				"movb     %%cl,%%al;"
				"and     $2,%%eax;" 
				"shl     $6,%%eax;"
				"or      %%eax,%%edx;"
				"movb     %%cl,%%al;"
				"and     $4,%%eax;"
				"shl     $4,%%eax;"
				"or      %%eax,%%edx;"
				"movb     %%cl,%%al;"
				"and     $8,%%eax;"
				"shl     $2,%%eax;"
				"or      %%eax,%%edx;"
				"movb     %%cl,%%al;"
				"and     $0x10,%%eax;"
				"shr     $2,%%al;"
				"or      %%eax,%%edx;"
				"movb    %%cl,%%al;"
				"and     $0x20,%%eax;"
				"shr     $2,%%al;"
				"or      %%eax,%%edx;"
				"movb    %%cl,%%al;"
				"and     $0x40,%%eax;"
				"shr     $2,%%al;"
				"or      %%eax,%%edx;"
				"shr     $7,%%cl;"
				"or      %%ecx,%%edx;"
				"movb     %%dl,%0;"
				:"=r"(tmp)
		     	:"r"(tmp)       
            	:"%ecx","%edx");
		inputbuf[index]=tmp;
	}
	return 0;
}
