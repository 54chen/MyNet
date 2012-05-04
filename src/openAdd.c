/* $OpenAAPD: aapd.c,v 0.1-beta 13/09/2005 18:49:17 whyx Exp $ */
/*
 * Copyright (C) 2005 Andrea Di Pasquale (whyx)
 * <<A HREF="mailto:whyx@openbeer.it">whyx@openbeer.it</A>>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
＃i nclude <stdio.h>
＃i nclude <stdlib.h>
＃i nclude <string.h>
＃i nclude <unistd.h>
＃i nclude <dirent.h>
＃i nclude <fcntl.h>
＃i nclude <errno.h>
＃i nclude <err.h>
＃i nclude <sys/types.h>
＃i nclude <sys/socket.h>
＃i nclude <sys/ioctl.h>
＃i nclude <sys/param.h>
＃i nclude <sys/sysctl.h>
＃i nclude <sys/time.h>
＃i nclude <net/if.h>
＃i nclude <net/if_dl.h>
＃i nclude <net/if_media.h>
＃i nclude <net/bpf.h>
＃i nclude <net/route.h>
＃i nclude <netinet/in.h>
＃i nclude <netinet/if_ether.h>
＃i nclude <arpa/inet.h>
#define ETHER_ADDR_LEN          6
#define ETHER_ADDRSTRLEN        18
#define       INET_ADDR_LEN              4
#define       ARPOP_ALL              3
int        main(int, char **);
void        check_uid_main(void);
int        parse_options_main(int, char **, char []);
void          daemon_main(void);
int        open_interface_bpf(void);
void        close_interface_bpf(int);
int        check_interface_bpf(int, char [], int);
void    write_arp_filter_bpf(int, unsigned short, unsigned long);
int        open_info_interface(void);
void        close_info_interface(int);
int        check_name_info_interface(int, int, char [], int);
char   *find_name_info_interface(int, int);
void        read_name_info_interface(int, int, char []);
void         read_mac_info_interface(void);
void       read_ipv4_info_interface(int);
void        build_info_interface(int, char []);
int        open_info_arp_cache(void);
void        close_info_arp_cache(int);
void        refresh_entrys_info_arp_cache(int, int);
void        build_info_arp_cache(int);
unsigned 
char   *open_info_arp_packet(void);
void    close_info_arp_packet(unsigned char *);
void    create_info_arp_packet(unsigned char *, unsigned short, char [], char []);
void    write_info_arp_packet(int, unsigned char *);
void    build_info_arp_packet(int, unsigned short, char [], char []);
unsigned 
char   *open_info_arp_type(int);
void       close_info_arp_type(unsigned char *);
void    check_info_arp_type(int, unsigned char *);
void       read_info_arp_type(int, unsigned char *);
void       build_info_arp_type(int);
char *errin[8] = {
       "Uid isn't root user uid (0)",
       
        "Ethernet interfaces not found",
       "isn't an ethernet interface",
       "isn't up mode",
       "Kernel bpf filter out of date",
       "Kernel bpf buffer out of size",
       "Kernel arp cache entry out of size",
       "Kernel bpf device not found"
};
#define       ERRINUID              0
#define       ERRINNFINTERFACE       1
#define ERRINNDCINTERFACE       2
#define ERRINNFUPINTERFACE       3
#define ERRINDCBPF              4
#define ERRINBUFBPF              5
#define       ERRINBUFARPCACHE       6
#define       ERRINNFBPF              7
struct info_interface {
        char name[IF_NAMESIZE];
        char mac[ETHER_ADDRSTRLEN];
        char ipv4[INET_ADDRSTRLEN];
} interface; 
struct info_arp_packet {
        unsigned char ether_dhost[ETHER_ADDR_LEN];
        unsigned char ether_shost[ETHER_ADDR_LEN];
        unsigned short ether_type;
        
        unsigned short ar_hrd;
#define ARPHRD_ETHER    1
        unsigned short ar_pro;
        unsigned char ar_hln;
        unsigned char ar_pln;
        unsigned short ar_op;
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
        unsigned char ar_sha[ETHER_ADDR_LEN];
        unsigned char ar_spa[INET_ADDR_LEN];
        unsigned char ar_tha[ETHER_ADDR_LEN];
        unsigned char ar_tpa[INET_ADDR_LEN];
       unsigned char payload[18];
} arp_packet;
struct info_arp_type {
       char mac[ETHER_ADDRSTRLEN];
} arp_type;
int
main(argc, argv)
       int argc;
       char **argv;
{
       int fd;
       char name[IF_NAMESIZE];
        check_uid_main();
       if (parse_options_main(argc, argv, name) != 0)
              daemon_main();
       fd = open_interface_bpf();
       build_info_interface(fd, name);
       build_info_arp_cache(fd);
       build_info_arp_type(fd);
       close_interface_bpf(fd);
       return 0;
}
void
check_uid_main(void)
{
        if (getuid())
              errx(1, "%s", errin[ERRINUID]);
}
int
parse_options_main(argc, argv, name)
       int argc;
       char **argv, name[IF_NAMESIZE];
{
        int gopt, debug = 0; 
        
        name[0] = '\0';
       while ((gopt = getopt(argc, argv, "i:dvh")) != -1)
                switch(gopt) {
                      case 'i':
                              strlcpy(name, optarg, IF_NAMESIZE);
                              break;
              case 'd':
                     debug = 1;
                     break;
              case 'v':
                     printf("OpenAAPD 0.1-beta (c) 2005 Andrea Di Pasquale (whyx)\n");
                     exit(1);
              case 'h':
              case '?':
                     printf("Usage: aapd [-i {interface | auto}] [-d] [-vh]\n");
                     exit(1);
              }
       argc -= optind;
        argv += optind;
       return debug;
}
void
daemon_main(void)
{
        int fd;
        switch (fork()) {
        case -1:
                    errx(1, "%s", strerror(errno));
        case 0:
                      break;
        default:
                    _exit(1);
        }
        if (setsid() < 0)
                errx(1, "%s", strerror(errno));
        if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
                dup2(fd, STDIN_FILENO);
                dup2(fd, STDOUT_FILENO);
                if (fd > 2)
                        close(fd);
        }
}
int
open_interface_bpf(void)
{
       int fd;
        char *interface;
        DIR *dir;
        struct dirent *dr;
        struct bpf_version bv;
        if ((dir = opendir("/dev")) == NULL)
                errx(1, "%s", strerror(errno));
        while ((dr = readdir(dir)) != NULL) {
                if (strstr(dr->d_name, "bpf")) {
                     if ((interface = calloc(strlen("/dev/") + strlen(dr->d_name) + 1, sizeof(char))) == NULL)
                                errx(1, "%s", strerror(errno));
                        strlcpy(interface, "/dev/", strlen("/dev/") + 1);
                        strlcat(interface, dr->d_name, strlen("/dev/") + strlen(dr->d_name) + 1);
                        
                     if ((fd = open(interface, O_RDWR)) < 0) {
                                free(interface);
                                continue;
                        } else {
                                free(interface);
                                break;
                        }
                }
        }
        if (fd < 0)
                errx(1, "%s", strerror(errno));
       if (dr == NULL)
              errx(1, "%s", errin[ERRINNFBPF]);
        if (ioctl(fd, BIOCVERSION, &bv) < 0)
                errx(1, "%s", strerror(errno));
        if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
                errx(1, "%s", errin[ERRINDCBPF]);
        if (closedir(dir) < 0)
                errx(1, "%s", strerror(errno));
       return fd;
}
void
close_interface_bpf(fd)
       int fd;
{
        if (close(fd) < 0)
                errx(1, "%s", strerror(errno));
}
int
check_interface_bpf(fd, name, opt)
       int fd, opt;
       char name[IF_NAMESIZE];
{
       int size, i;
       unsigned int dt;
        struct ifreq ifr;
       for (size = 32768; size != 0; size >>= 1) {
                    ioctl(fd, BIOCSBLEN, &size);     
                    strlcpy(ifr.ifr_name, name, IF_NAMESIZE);
                    if (ioctl(fd, BIOCSETIF, &ifr) >= 0)
                      break;
                    if (errno != ENOBUFS)
                        errx(1, "%s", strerror(errno));
       }     
       if (size == 0)
              errx(1, "%s", errin[ERRINBUFBPF]);
       if (ioctl(fd, BIOCGBLEN, &size) < 0)
              errx(1, "%s", strerror(errno));
       if (ioctl(fd, BIOCGDLT, &dt) < 0)
                errx(1, "%s", strerror(errno));
        if (dt != DLT_EN10MB)
              if (opt == 0)
                     errx(1, "%s %s", name, errin[ERRINNDCINTERFACE]);
              else
                     return 1;
       i = 1;
          if (ioctl(fd, BIOCIMMEDIATE, &i) < 0)
              errx(1, "%s", strerror(errno));
       if (ioctl(fd, FIONBIO, &i) < 0)
              errx(1, "%s", strerror(errno));
       return 0;
}
void
write_arp_filter_bpf(fd, type, mode)
       int fd;
       unsigned short type;
       unsigned long mode;
{
       if (type == ARPOP_ALL) {
              struct bpf_insn insns_arp_all[] = {
                       BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_ARP, 0, 1),
                       BPF_STMT(BPF_RET | BPF_K, sizeof(struct info_arp_packet)),
                       BPF_STMT(BPF_RET | BPF_K, 0)
               };
               struct bpf_program filter = {
                       sizeof insns_arp_all / sizeof(insns_arp_all[0]),
                       insns_arp_all
               };
               if (ioctl(fd, mode, &filter) < 0)
                       errx(1, "%s", strerror(errno));
       } else {
              struct bpf_insn insns_arp_type[] = {
                                   BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
                                   BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_ARP, 0, 1),
                                   BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),
                                   BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, type, 0, 1),
                                   BPF_STMT(BPF_RET | BPF_K, sizeof(struct info_arp_packet)),
                                   BPF_STMT(BPF_RET | BPF_K, 0)
                     };
              struct bpf_program filter = {
                                   sizeof insns_arp_type / sizeof(insns_arp_type[0]),
                                   insns_arp_type
                     };
              
              if (ioctl(fd, mode, &filter) < 0)
                                   errx(1, "%s", strerror(errno));
       }
}
int
open_info_interface(void)
{
       int sd;
       if ((sd = socket(PF_INET, SOCK_RAW, 0)) < 0)
                errx(1, "%s", strerror(errno));
       return sd;
}
void
close_info_interface(sd)
       int sd;
{
        if (close(sd) < 0)
                errx(1, "%s", strerror(errno));
}
int
check_name_info_interface(fd, sd, name, opt)
       int fd, sd, opt;
       char name[IF_NAMESIZE];
{
        struct ifreq ifr;
       if (check_interface_bpf(fd, name, opt))
              return 1;
       
       strlcpy(ifr.ifr_name, name, IF_NAMESIZE); 
       if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0)
                errx(1, "%s", strerror(errno));
        if ((ifr.ifr_flags & IFF_UP) == 0 ||
            ifr.ifr_flags & IFF_LOOPBACK ||
            ifr.ifr_flags & IFF_POINTOPOINT) 
              if (opt == 0)
                       errx(1, "%s", errin[ERRINNFUPINTERFACE]);
              else
                     return 1;
       return 0;
}
char *
find_name_info_interface(fd, sd)
       int fd, sd;
{
        int n, c;
        unsigned int buf_size;
        char *buf;
        struct ifconf ifc;
        struct ifreq *cur, *end, *next;
        for (buf_size = 8192; ifc.ifc_len >= buf_size; buf_size *= 2) {
                if (buf_size != 8192)
                     free(buf);
              if ((buf = calloc(buf_size, sizeof(char))) == NULL)
                        errx(1, "%s", strerror(errno));
                ifc.ifc_len = buf_size;
                ifc.ifc_buf = buf;
                memset(buf, 0, buf_size);
                if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
                        free(buf);
                        errx(1, "%s", strerror(errno));
                }
        }
       
       for (cur = (struct ifreq *)buf, end = (struct ifreq *)(buf + ifc.ifc_len); cur < end; cur = next) {
                if ((n = cur->ifr_addr.sa_len + IF_NAMESIZE) < sizeof(struct ifreq))
                        next = cur + 1;
                else     
                        next = (struct ifreq *)((char *)cur + n);
 
                if ((c = check_name_info_interface(fd, sd, cur->ifr_name, 1)) == 0)
                     break;
       }               
        free(buf); 
       if (c != 0)
              errx(1, "%s", errin[ERRINNFINTERFACE]);
       else       
              return cur->ifr_name;
}
void
read_name_info_interface(fd, sd, name)
       int fd, sd;
       char name[IF_NAMESIZE];
{                       
        if (strncmp(name, "auto", IF_NAMESIZE) == 0 || name[0] == '\0')
                strlcpy(name, find_name_info_interface(fd, sd), IF_NAMESIZE);
        else            
                check_name_info_interface(fd, sd, name, 0);
        strlcpy(interface.name, name, IF_NAMESIZE);
}
void
read_mac_info_interface(void)
{
        int mib[6];
        size_t len;
        char *buf, *next, *end; 
        struct if_msghdr *ifm;
        struct sockaddr_dl *sdl;
        mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = PF_LINK;
        mib[4] = NET_RT_IFLIST;
        mib[5] = 0;
        if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
                errx(1, "%s", strerror(errno));
        if ((buf = calloc(len, sizeof(char))) == NULL)
               errx(1, "%s", strerror(errno));
        if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
                free(buf);
               errx(1, "%s", strerror(errno));
       }
        
        for (end = buf + len, next = buf; next < end; next += ifm->ifm_msglen) {
                ifm = (struct if_msghdr *)next;
              if (ifm->ifm_type == RTM_IFINFO) {
                        sdl = (struct sockaddr_dl *)(ifm + 1);
                     if (strncmp(sdl->sdl_data, interface.name, sdl->sdl_nlen) == 0) {
                                strlcpy(interface.mac, 
                                   ether_ntoa((struct ether_addr *)LLADDR(sdl)), 
                                   ETHER_ADDRSTRLEN);
                            break;
                        }
                }
        }
        free(buf);
}
void
read_ipv4_info_interface(sd)
       int sd;
{       
        struct ifreq ifr;
        struct in_addr ia;
        strlcpy(ifr.ifr_name, interface.name, IF_NAMESIZE);
        if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) 
              errx(1, "%s", strerror(errno));
        memcpy(&ia.s_addr, ifr.ifr_addr.sa_data + 2, INET_ADDR_LEN);
        
       strlcpy(interface.ipv4, inet_ntoa(ia), INET_ADDRSTRLEN);
}
void
build_info_interface(fd, name)
       int fd;
       char name[IF_NAMESIZE];
{
        int sd;
        sd = open_info_interface();
        
       read_name_info_interface(fd, sd, name);
        read_mac_info_interface();
        read_ipv4_info_interface(sd);
       
       printf("Info %s interface card:\n", interface.name);
       printf("Mac: %s\n", interface.mac);
       printf("Ipv4: %s\n", interface.ipv4);
       close_info_interface(sd);
}
int
open_info_arp_cache(void)
{
       int sd;
       if ((sd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
              errx(1, "%s", strerror(errno));
       return sd;
}
void
close_info_arp_cache(sd)
       int sd;
{
        if (close(sd) < 0)
                errx(1, "%s", strerror(errno));
}
   
void
refresh_entrys_info_arp_cache(fd, sd)
       int fd, sd;
{
       int mib[6];
       size_t len;
       char *buf, *end, *next; 
       struct rt_msghdr *rtm;
       struct sockaddr_dl *sdl;
       struct sockaddr_in *sin;
       
       mib[0] = CTL_NET;
       mib[1] = PF_ROUTE;
       mib[2] = 0; 
       mib[3] = PF_INET;
       mib[4] = NET_RT_FLAGS;
       mib[5] = RTF_LLINFO;
       if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
                errx(1, "%s", strerror(errno));
        if (len == 0)
                errx(1, "%s", errin[ERRINBUFARPCACHE]);
        if ((buf = calloc(len, sizeof(char))) == NULL)
                errx(1, "%s", strerror(errno));
        if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
                free(buf);
                errx(1, "%s", strerror(errno));
        }       
       
       for (end = buf + len, next = buf; next < end; next += rtm->rtm_msglen) {
              rtm = (struct rt_msghdr *)next;
              sin = (struct sockaddr_in *)(rtm + 1);
                sdl = (struct sockaddr_dl *)(sin + 1);
              if (strncmp(sdl->sdl_data, interface.name, sdl->sdl_nlen) == 0) {
                     build_info_arp_packet(fd, ARPOP_REPLY, "ff:ff:ff:ff:ff:ff",
                                              inet_ntoa(*(struct in_addr *)&sin->sin_addr.s_addr));
                     build_info_arp_packet(fd, ARPOP_REQUEST, "ff:ff:ff:ff:ff:ff",
                                              inet_ntoa(*(struct in_addr *)&sin->sin_addr.s_addr));
       
                     printf("Anti Arp Poisoning to Mac %s, Ipv4 %s by Mac %s, Ipv4 %s (On Arp Cache)\n",
                            ether_ntoa((struct ether_addr *)LLADDR(sdl)),
                            inet_ntoa(*(struct in_addr *)&sin->sin_addr.s_addr),
                            interface.mac, interface.ipv4);
              }
       }
       free(buf);
}
void
build_info_arp_cache(fd)
       int fd;
{
        int sd;
        sd = open_info_arp_cache();
        
       refresh_entrys_info_arp_cache(fd, sd);
        
       close_info_arp_cache(sd);
}
unsigned char *
open_info_arp_packet(void)
{
       unsigned char *packet;
       if ((packet = malloc(sizeof(struct info_arp_packet))) == NULL)
                errx(1, "%s", strerror(errno));
                
        memset(packet, 0, sizeof(struct info_arp_packet));
       return packet;
}
void
close_info_arp_packet(packet)
       unsigned char *packet;
{
       free(packet);
}
void
create_info_arp_packet(packet, type, tha, tpa)
       unsigned char *packet;
       unsigned short type;
       char tha[ETHER_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
{
       struct in_addr ia_src, ia_dst;
       memcpy(arp_packet.ether_dhost, (unsigned char *)ether_aton(tha), ETHER_ADDR_LEN);
       memcpy(arp_packet.ether_shost, (unsigned char *)ether_aton(interface.mac), ETHER_ADDR_LEN);
        arp_packet.ether_type = htons(ETHERTYPE_ARP);
        arp_packet.ar_hrd = htons(ARPHRD_ETHER);
        arp_packet.ar_pro = htons(ETHERTYPE_IP);
        arp_packet.ar_hln = ETHER_ADDR_LEN;
        arp_packet.ar_pln = INET_ADDR_LEN;
        arp_packet.ar_op  = htons(type);
       memcpy(arp_packet.ar_sha, (unsigned char *)ether_aton(interface.mac), ETHER_ADDR_LEN);
        inet_aton(interface.ipv4, &ia_src);
        memcpy(arp_packet.ar_spa, &ia_src.s_addr, INET_ADDR_LEN);
        memcpy(arp_packet.ar_tha, (unsigned char *)ether_aton(tha), ETHER_ADDR_LEN);
        inet_aton(tpa, &ia_dst);
        memcpy(arp_packet.ar_tpa, &ia_dst.s_addr, INET_ADDR_LEN);
       memset(arp_packet.payload, 0, 18);
        memcpy(packet, &arp_packet, sizeof(struct info_arp_packet));
}
void
write_info_arp_packet(fd, packet)
       int fd;
       unsigned char *packet;
{
       if (write(fd, packet, sizeof(struct info_arp_packet)) != sizeof(struct info_arp_packet))
                errx(1, "%s", strerror(errno));
}
void
build_info_arp_packet(fd, type, tha, tpa)
       int fd;
       unsigned short type;
       char tha[ETHER_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
{
       unsigned char *packet;
       packet = open_info_arp_packet();
       create_info_arp_packet(packet, type, tha, tpa);
       write_arp_filter_bpf(fd, type, BIOCSETWF);
       write_info_arp_packet(fd, packet);
       close_info_arp_packet(packet);
}
unsigned char *
open_info_arp_type(fd)
       int fd;
{
       int size;
       unsigned char *packet;
       if (ioctl(fd, BIOCGBLEN, &size) < 0)
                errx(1, "%s", strerror(errno));
        if ((packet = calloc(size, sizeof(char))) == NULL)
                errx(1, "%s", strerror(errno));
       return packet;
}
void
close_info_arp_type(packet)
       unsigned char *packet;
{
       free(packet);
}
void
check_info_arp_type(fd, packet)
       int fd;
       unsigned char *packet;
{       
       struct info_arp_packet *arp_packet_;
       arp_packet_ = (struct info_arp_packet *)(packet + ((struct bpf_hdr *)packet)->bh_hdrlen);
       if (! strcmp(interface.ipv4, inet_ntoa(*(struct in_addr *)&arp_packet_->ar_spa)))
                   return;
       if (! strcmp(arp_type.mac, ether_ntoa((struct ether_addr *)arp_packet_->ar_sha)))
                    return;
       printf("Arp %s to Mac %s, Ipv4 %s ",
              (arp_packet_->ar_op == ARPOP_REQUEST ? "Request" : "Reply"),
              ether_ntoa((struct ether_addr *)arp_packet_->ar_tha),
              inet_ntoa(*(struct in_addr *)&arp_packet_->ar_tpa));
       printf("by Mac %s, Ipv4 %s (On The Fly)\n",
              ether_ntoa((struct ether_addr *)arp_packet_->ar_sha),
              inet_ntoa(*(struct in_addr *)&arp_packet_->ar_spa));
                     
       strlcpy(arp_type.mac, ether_ntoa((struct ether_addr *)arp_packet_->ar_sha), ETHER_ADDRSTRLEN);
       if (ntohs(arp_packet_->ar_op) == ARPOP_REQUEST)
                   sleep(1);
       build_info_arp_packet(fd, ARPOP_REPLY, "ff:ff:ff:ff:ff:ff",
                              inet_ntoa(*(struct in_addr *)&arp_packet_->ar_spa));
              build_info_arp_packet(fd, ARPOP_REQUEST, "ff:ff:ff:ff:ff:ff",
                              inet_ntoa(*(struct in_addr *)&arp_packet_->ar_spa));
       printf("Anti Arp Poisoning to Mac %s, Ipv4 %s ",
               ether_ntoa((struct ether_addr *)arp_packet_->ar_sha),
                     inet_ntoa(*(struct in_addr *)&arp_packet_->ar_spa));
       printf("by Mac %s, Ipv4 %s (On The Fly)\n",
               ether_ntoa((struct ether_addr *)arp_packet_->ar_tha),
                     inet_ntoa(*(struct in_addr *)&arp_packet_->ar_tpa));
}
void
read_info_arp_type(fd, packet)
        int fd;
        unsigned char *packet;
{      
       int size; 
       unsigned int len;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (select(fd + 1, &fds, NULL, NULL, NULL) < 0)
                errx(1, "%s", strerror(errno));
        if (FD_ISSET(fd, &fds)) {
              if (ioctl(fd, BIOCGBLEN, &size) < 0)
                       errx(1, "%s", strerror(errno));
       
              if ((len = read(fd, packet, size)) < 0)
                     errx(1, "%s", strerror(errno));
              if (len == 0)
                     return;
              
              check_info_arp_type(fd, packet);
       }
        FD_CLR(fd, &fds);
}
void
build_info_arp_type(fd)
       int fd;
{
       unsigned char *packet;
       
       packet = open_info_arp_type(fd);
       
       write_arp_filter_bpf(fd, ARPOP_ALL, BIOCSETF);
       read_info_arp_type(fd, packet);
       close_info_arp_type(packet);
       build_info_arp_type(fd);
