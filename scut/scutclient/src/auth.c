/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

int Authentication(const char *UserName, const char *Password, const char *DeviceName);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <pcap.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "debug.h"

// 自定义常量
uint8_t ipinfo[100]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x23,0xff,0xff,
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x23,0x32,0x2e,0x31,
0x2e,0x33,0x23,0x45,0x58,0x54,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00};
uint8_t md5info[100]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x23,0xff,0xff,
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x23,0x32,0x2e,0x31,
0x2e,0x33,0x23,0x45,0x58,0x54,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00};

int ipinfonum;
uint8_t checksum[131]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,
0x2e,0x65,0x78,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x33,0x37,0x35,0x30,0x30,
0x00,0x00,0x13,0x11,0x00,0x28,0x1a,0x28,0x00,0x00,0x13,0x11,0x17,0x22,0x91,0x62,
0x61,0x65,0x61,0x65,0x61,0x69,0x63,0x68,0x95,0x69,0x66,0x94,0x94,0x63,0x95,0x60,
0x68,0x94,0x68,0x94,0x68,0x63,0x96,0x91,0x61,0x9a,0xa7,0x94,0x9f,0xab,0x00,0x00,
0x13,0x11,0x18,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00};

static int times=20;
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const char H3C_VERSION[16]="EN V2.40-0335"; // 华为客户端版本号
const char H3C_KEY[]      ="HuaWei3COM1X";  // H3C的固定密钥

// 子函数声明
static void SendStartPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendLogoffPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendResponseIdentity(pcap_t *adhandle,
			const uint8_t request[],
			const uint8_t ethhdr[]);
static void SendResponseMD5(pcap_t *adhandle,
		const uint8_t request[],
		const uint8_t ethhdr[]);

static void GetMacFromDevice(uint8_t mac[6], const char *devicename);


void GetInfoFromDevice(const char *UserName, const char *Password);
void check(u_char *buf);
u_char encode(u_char base);
char ipaddr[20]={0};
char mask[20]={0};
char gateway[20]={0};
char dns[20]={0};
size_t userlen,iplen=0;

/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

int Authentication(const char *UserName, const char *Password, const char *DeviceName)
{
	userlen=strlen(UserName);
	GetInfoFromDevice(UserName, Password);
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*adhandle; // adapter handle
	uint8_t	MAC[6];
	char	FilterStr[100];
	struct bpf_program	fcode;
	const int DefaultTimeout=60000;//设置接收超时参数，单位ms

	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(-1);
	}

	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
							MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);


	START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header;
		const uint8_t	*captured;
		uint8_t	ethhdr[14]={0}; // ethernet header
		memcpy(ethhdr+0, MultcastAddr, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;
		uint8_t	ip[4]={0};	// ip address
		//uint8_t	capt[100]={0};
		//captured=capt;
		/* 主动发起认证会话 */
		SendStartPkt(adhandle, MAC);
		DPRINTF("SCUTclient: Start.\n");
		//SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
		//DPRINTF("Identity.\n");
		//SendResponseMD5(adhandle, captured, ethhdr, UserName, Password);
		//DPRINTF("MD5-Challenge.\n");
		/* 等待认证服务器的回应 */
		bool serverIsFound = false;
		while (!serverIsFound)
		{
			retcode = pcap_next_ex(adhandle, &header, &captured);
			if (retcode==1 && (EAP_Code)captured[18]==REQUEST)
			{
				serverIsFound = true;
				DPRINTF("Server( %02x:%02x:%02x:%02x:%02x:%02x )Is Found!\n",captured[0],captured[1],captured[2],captured[3],captured[4],captured[5]);
			}
			else
			{	// 延时后重试
				sleep(1);
				DPRINTF(".");
				SendStartPkt(adhandle, MAC);
				// NOTE: 这里没有检查网线是否接触不良或已被拔下
			}
		}

		// 填写应答包的报头(以后无须再修改)
		// 默认以单播方式应答802.1X认证设备发来的Request
		memcpy(ethhdr+0, captured+6, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 分情况应答下一个包
		if ((EAP_Type)captured[22] == IDENTITY)
		{	// 通常情况会收到包Request Identity，应回答Response Identity
			DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
			SendResponseIdentity(adhandle, captured, ethhdr);
			DPRINTF("[%d] SCUTclient: Response Identity.\n", (EAP_ID)captured[19]);
		}

		// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		// 进入循环体
		for (;;)
		{
			// 调用pcap_next_ex()函数捕获数据包
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				DPRINTF("."); // 若捕获失败，则等1秒后重试
				sleep(1);     // 直到成功捕获到一个数据包后再跳出
				// NOTE: 这里没有检查网线是否已被拔下或插口接触不良
			}

			// 根据收到的Request，回复相应的Response包
			if ((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
				 case IDENTITY:
					DPRINTF("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
					SendResponseIdentity(adhandle, captured, ethhdr);
					DPRINTF("[%d] SCUTclient: Response Identity.\n", (EAP_ID)captured[19]);
					break;
				 case MD5:
					DPRINTF("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
					SendResponseMD5(adhandle, captured, ethhdr);
					DPRINTF("[%d] SCUTclient: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
					break;
				 default:
					DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
					DPRINTF("Error! Unexpected request type\n");
					exit(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{	// 处理认证失败信息
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				uint8_t infocode[2] = {captured[28],captured[29]};
				const char *msg = (const char*) &captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09)
				{	// 输出错误提示消息
					if (1==times)
					{
						DPRINTF("Reconnection is failed.---from Forward @SCUT\n");
						exit(-1);
					}
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2535:Service is paused
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效


					if (infocode[0]==0x32 && infocode[1]==0x37 && times>1)
					{
						times--;
						sleep(1);
						goto START_AUTHENTICATION;
					}
					if (infocode[0]==0x00 && infocode[1]==0x00 && times>1)
					{
						times--;
						sleep(1);
						goto START_AUTHENTICATION;
					}







					exit(-1);
				}
				else if (errtype==0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{	// 遇此情况客户端立刻发起新的认证会话
					sleep(1);
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					exit(-1);
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%d] Server: Success.\n", captured[19]);
				// 刷新IP地址
				times=20;
			}
			else
			{
				DPRINTF("[%d] Server: (H3C data)\n", captured[19]);
				// TODO: 这里没有处理华为自定义数据包
			}
		}
	}
	return (0);
}



static
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{

	int	fd;
	int	err;
	struct ifreq	ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return;
}


static
void SendStartPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[149];

	// Ethernet Header (14 Bytes)
	memcpy(packet, BroadcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x01;	// Type=Start
	packet[16] = packet[17] =0x00;// Length=0x0000
	int i=18;
	for(i=18;i<=148;i++)
	packet[i] =checksum[i-18];// Length=0x0000
	// 为了兼容不同院校的网络配置，这里发送两遍Start包
	// 1、广播发送Strat包
//	pcap_sendpacket(handle, packet, i);
	// 2、多播发送Strat包
	memcpy(packet, MultcastAddr, 6);
	//sleep(10);
//	DPRINTF("\n*************************************************\n");
//	int m,n=0;
//	for(m=0;m<=i-1;m++)
//	{
//		n++;
//		if(n==17)
//		{
//			DPRINTF("\n");
//			n=1;
//		}
//		DPRINTF("%02x ",packet[m]);
//	}
	pcap_sendpacket(handle, packet, i);
}

static
void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[])
{
	uint8_t	response[300];
	int i;
	uint16_t eaplen;
//	int usernamelen;
//	assert(/*(EAP_Code)*/request[18] == REQUEST);
//	assert(/*(EAP_Type)*/request[22] == IDENTITY
//	     ||/*(EAP_Type)*/request[22] == AVAILABLE); // 兼容中南财经政法大学情况

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		//response[16~17]留空	// Length

		// Extensible Authentication Protocol
		// {
			response[18] = /*(EAP_Code)*/ RESPONSE;	// Code
			response[19] = request[19];		// ID
			//response[20~21]留空			// Length
			response[22] = /*(EAP_Type)*/ IDENTITY;	// Type
			// Type-Data
			// {
				i = 23;

		for(i=23;i<=30+userlen+iplen;i++)
	response[i] =ipinfo[i-23];
		for(i=31+userlen+iplen;i<=162+userlen+iplen;i++)
	response[i] =checksum[i-31-userlen-iplen];
	// 补填前面留空的两处Length
	eaplen =htons(13+userlen+iplen);
	memcpy(response+16, &eaplen, sizeof(eaplen));// Length
	memcpy(response+20, &eaplen, sizeof(eaplen));// Length
//	response[17] =13+userlen+iplen;
//	response[21] =13+userlen+iplen;
	memcpy(response, MultcastAddr, 6);
	// 发送
//	DPRINTF("\n*************************************************\n");
//	int m,n=0;
//	for(m=0;m<=i-2;m++)
//	{
//		n++;
//		if(n==17)
//		{
//			DPRINTF("\n");
//			n=1;
//		}
//		DPRINTF("%02x ",response[m]);
//	}
	pcap_sendpacket(adhandle, response, i-1);
	return;
}


static
void SendResponseMD5(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[])
{
	uint16_t eaplen;
	uint8_t  response[300];

//	assert(/*(EAP_Code)*/request[18] == REQUEST);
//	assert(/*(EAP_Type)*/request[22] == MD5);





	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		eaplen =htons(35+userlen+iplen);
		memcpy(response+16, &eaplen, sizeof(eaplen));// Length
//		response[17] =13+userlen+iplen;
//		response[21] =13+userlen+iplen;
		// Extensible Authentication Protocol
		// {
		response[18] = /*(EAP_Code)*/ RESPONSE;// Code
		response[19] = request[19];		// ID


		memcpy(response+20, &eaplen, sizeof(eaplen));// Length
		response[22] = /*(EAP_Type)*/ MD5;	// Type
		response[23] = 16;		// Value-Size: 16 Bytes
		unsigned int i=24;

		for(i=24;i<=52+userlen+iplen;i++)
			response[i] =md5info[i-24];
		for(;i<=184+userlen+iplen;i++)
			response[i] =checksum[i-53-userlen-iplen];
		memcpy(response, MultcastAddr, 6);
		// }
	// }
//	DPRINTF("\n*************************************************\n");
//	int m,n=0;
//	for(m=0;m<=i-2;m++)
//	{
//		n++;
//		if(n==17)
//		{
//			DPRINTF("\n");
//			n=1;
//		}
//		DPRINTF("%02x ",response[m]);
//	}
	pcap_sendpacket(handle, response, i-1);
}


static
void SendLogoffPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[149];

	// Ethernet Header (14 Bytes)
	memcpy(packet, BroadcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x02;	// Type=Logoff
	packet[16] = packet[17] =0x00;// Length=0x0000
	int i=18;
	for(i=18;i<=148;i++)
	packet[i] =checksum[i-18];// Length=0x0000
	// 为了兼容不同院校的网络配置，这里发送两遍Start包
	// 1、广播发送Strat包
//	pcap_sendpacket(handle, packet, i);
	// 2、多播发送Strat包
	sleep(10);
	memcpy(packet, MultcastAddr, 6);
	pcap_sendpacket(handle, packet, i);
}

// 函数: XOR(data[], datalen, key[], keylen)
//
// 使用密钥key[]对数据data[]进行异或加密
//（注：该函数也可反向用于解密）

void GetInfoFromDevice(const char *UserName, const char *Password)
{
	FILE   *stream;
	char    buf[100]={0};
	int	count = 0;

	stream = popen( "uci get network.wan.ipaddr", "r" );
	count = fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
	memcpy(ipaddr, buf , count-1);
	pclose( stream );

	iplen=strlen(ipaddr);
	stream = popen( "uci get network.wan.netmask", "r" );
	count = fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
	memcpy(mask, buf , count-1);
	pclose( stream );

	stream = popen( "uci get network.wan.gateway", "r" );
	count = fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
	memcpy(gateway, buf , count-1);
	pclose( stream );

	stream = popen( "uci get network.wan.dns | cut -d ' ' -f 1", "r" );
	count = fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
	memcpy(dns, buf , count-1);
	pclose( stream );

	unsigned char  checkinfo[23];

	int iphex[4];

	sscanf(ipaddr,"%d.%d.%d.%d",&iphex[0],&iphex[1],&iphex[2],&iphex[3]);
	checkinfo[5]=iphex[0];
	checkinfo[6]=iphex[1];
	checkinfo[7]=iphex[2];
	checkinfo[8]=iphex[3];

	sscanf(mask,"%d.%d.%d.%d",&iphex[0],&iphex[1],&iphex[2],&iphex[3]);
	checkinfo[9]=iphex[0];
	checkinfo[10]=iphex[1];
	checkinfo[11]=iphex[2];
	checkinfo[12]=iphex[3];

	sscanf(gateway,"%d.%d.%d.%d",&iphex[0],&iphex[1],&iphex[2],&iphex[3]);
	checkinfo[13]=iphex[0];
	checkinfo[14]=iphex[1];
	checkinfo[15]=iphex[2];
	checkinfo[16]=iphex[3];

	sscanf(dns,"%d.%d.%d.%d",&iphex[0],&iphex[1],&iphex[2],&iphex[3]);
	checkinfo[17]=iphex[0];
	checkinfo[18]=iphex[1];
	checkinfo[19]=iphex[2];
	checkinfo[20]=iphex[3];
	checkinfo[0]=0x00;
	checkinfo[1]=0x00;
	checkinfo[2]=0x13;
	checkinfo[3]=0x11;
	checkinfo[4]=0x00;

	check(checkinfo);

	memcpy(ipinfo, UserName, strlen(UserName));
	ipinfo[strlen(UserName)]=0x23;
	ipinfo[1+strlen(UserName)]=0x30;
	memcpy(ipinfo+2+strlen(UserName), ipaddr, strlen(ipaddr));
	ipinfo[2+strlen(UserName)+strlen(ipaddr)]=0x23;
	ipinfo[3+strlen(UserName)+strlen(ipaddr)]=0x32;
	ipinfo[4+strlen(UserName)+strlen(ipaddr)]=0x2e;
	ipinfo[5+strlen(UserName)+strlen(ipaddr)]=0x31;
	ipinfo[6+strlen(UserName)+strlen(ipaddr)]=0x2e;
	ipinfo[7+strlen(UserName)+strlen(ipaddr)]=0x33;

	int m=0;
	memcpy(md5info, Password, 16);
	if(strlen(Password)<=16)
	{	for(m=strlen(Password);m<=15;m++)
		{	md5info[m] = 0x0;
		}
	}
	memcpy(md5info+16, UserName, strlen(UserName));
	md5info[17+strlen(UserName)]=0x23;
	md5info[18+strlen(UserName)]=0x30;
	memcpy(md5info+19+strlen(UserName), ipaddr, strlen(ipaddr));
	md5info[19+strlen(UserName)+strlen(ipaddr)]=0x23;
	md5info[20+strlen(UserName)+strlen(ipaddr)]=0x32;
	md5info[21+strlen(UserName)+strlen(ipaddr)]=0x2e;
	md5info[22+strlen(UserName)+strlen(ipaddr)]=0x31;
	md5info[23+strlen(UserName)+strlen(ipaddr)]=0x2e;
	md5info[24+strlen(UserName)+strlen(ipaddr)]=0x33;
	md5info[25+strlen(UserName)+strlen(ipaddr)]=0x23;
	md5info[26+strlen(UserName)+strlen(ipaddr)]=0x45;
	md5info[27+strlen(UserName)+strlen(ipaddr)]=0x58;
	md5info[28+strlen(UserName)+strlen(ipaddr)]=0x54;
	md5info[16+strlen(UserName)]=md5info[34+strlen(UserName)];

	return;
}

void check(u_char *buf)
{
	u_char table[] =
	{
		0x00,0x00,0x21,0x10,0x42,0x20,0x63,0x30,0x84,0x40,0xA5,0x50,0xC6,0x60,0xE7,0x70,
		0x08,0x81,0x29,0x91,0x4A,0xA1,0x6B,0xB1,0x8C,0xC1,0xAD,0xD1,0xCE,0xE1,0xEF,0xF1,
		0x31,0x12,0x10,0x02,0x73,0x32,0x52,0x22,0xB5,0x52,0x94,0x42,0xF7,0x72,0xD6,0x62,
		0x39,0x93,0x18,0x83,0x7B,0xB3,0x5A,0xA3,0xBD,0xD3,0x9C,0xC3,0xFF,0xF3,0xDE,0xE3,
		0x62,0x24,0x43,0x34,0x20,0x04,0x01,0x14,0xE6,0x64,0xC7,0x74,0xA4,0x44,0x85,0x54,
		0x6A,0xA5,0x4B,0xB5,0x28,0x85,0x09,0x95,0xEE,0xE5,0xCF,0xF5,0xAC,0xC5,0x8D,0xD5,
		0x53,0x36,0x72,0x26,0x11,0x16,0x30,0x06,0xD7,0x76,0xF6,0x66,0x95,0x56,0xB4,0x46,
		0x5B,0xB7,0x7A,0xA7,0x19,0x97,0x38,0x87,0xDF,0xF7,0xFE,0xE7,0x9D,0xD7,0xBC,0xC7,
		0xC4,0x48,0xE5,0x58,0x86,0x68,0xA7,0x78,0x40,0x08,0x61,0x18,0x02,0x28,0x23,0x38,
		0xCC,0xC9,0xED,0xD9,0x8E,0xE9,0xAF,0xF9,0x48,0x89,0x69,0x99,0x0A,0xA9,0x2B,0xB9,
		0xF5,0x5A,0xD4,0x4A,0xB7,0x7A,0x96,0x6A,0x71,0x1A,0x50,0x0A,0x33,0x3A,0x12,0x2A,
		0xFD,0xDB,0xDC,0xCB,0xBF,0xFB,0x9E,0xEB,0x79,0x9B,0x58,0x8B,0x3B,0xBB,0x1A,0xAB,
		0xA6,0x6C,0x87,0x7C,0xE4,0x4C,0xC5,0x5C,0x22,0x2C,0x03,0x3C,0x60,0x0C,0x41,0x1C,
		0xAE,0xED,0x8F,0xFD,0xEC,0xCD,0xCD,0xDD,0x2A,0xAD,0x0B,0xBD,0x68,0x8D,0x49,0x9D,
		0x97,0x7E,0xB6,0x6E,0xD5,0x5E,0xF4,0x4E,0x13,0x3E,0x32,0x2E,0x51,0x1E,0x70,0x0E,
		0x9F,0xFF,0xBE,0xEF,0xDD,0xDF,0xFC,0xCF,0x1B,0xBF,0x3A,0xAF,0x59,0x9F,0x78,0x8F,
		0x88,0x91,0xA9,0x81,0xCA,0xB1,0xEB,0xA1,0x0C,0xD1,0x2D,0xC1,0x4E,0xF1,0x6F,0xE1,
		0x80,0x10,0xA1,0x00,0xC2,0x30,0xE3,0x20,0x04,0x50,0x25,0x40,0x46,0x70,0x67,0x60,
		0xB9,0x83,0x98,0x93,0xFB,0xA3,0xDA,0xB3,0x3D,0xC3,0x1C,0xD3,0x7F,0xE3,0x5E,0xF3,
		0xB1,0x02,0x90,0x12,0xF3,0x22,0xD2,0x32,0x35,0x42,0x14,0x52,0x77,0x62,0x56,0x72,
		0xEA,0xB5,0xCB,0xA5,0xA8,0x95,0x89,0x85,0x6E,0xF5,0x4F,0xE5,0x2C,0xD5,0x0D,0xC5,
		0xE2,0x34,0xC3,0x24,0xA0,0x14,0x81,0x04,0x66,0x74,0x47,0x64,0x24,0x54,0x05,0x44,
		0xDB,0xA7,0xFA,0xB7,0x99,0x87,0xB8,0x97,0x5F,0xE7,0x7E,0xF7,0x1D,0xC7,0x3C,0xD7,
		0xD3,0x26,0xF2,0x36,0x91,0x06,0xB0,0x16,0x57,0x66,0x76,0x76,0x15,0x46,0x34,0x56,
		0x4C,0xD9,0x6D,0xC9,0x0E,0xF9,0x2F,0xE9,0xC8,0x99,0xE9,0x89,0x8A,0xB9,0xAB,0xA9,
		0x44,0x58,0x65,0x48,0x06,0x78,0x27,0x68,0xC0,0x18,0xE1,0x08,0x82,0x38,0xA3,0x28,
		0x7D,0xCB,0x5C,0xDB,0x3F,0xEB,0x1E,0xFB,0xF9,0x8B,0xD8,0x9B,0xBB,0xAB,0x9A,0xBB,
		0x75,0x4A,0x54,0x5A,0x37,0x6A,0x16,0x7A,0xF1,0x0A,0xD0,0x1A,0xB3,0x2A,0x92,0x3A,
		0x2E,0xFD,0x0F,0xED,0x6C,0xDD,0x4D,0xCD,0xAA,0xBD,0x8B,0xAD,0xE8,0x9D,0xC9,0x8D,
		0x26,0x7C,0x07,0x6C,0x64,0x5C,0x45,0x4C,0xA2,0x3C,0x83,0x2C,0xE0,0x1C,0xC1,0x0C,
		0x1F,0xEF,0x3E,0xFF,0x5D,0xCF,0x7C,0xDF,0x9B,0xAF,0xBA,0xBF,0xD9,0x8F,0xF8,0x9F,
		0x17,0x6E,0x36,0x7E,0x55,0x4E,0x74,0x5E,0x93,0x2E,0xB2,0x3E,0xD1,0x0E,0xF0,0x1E
	};
	u_char *check = buf + 0x15;
	int i, index;
	for (i=0; i<0x15; i++)
	{
		index = check[0] ^ buf[i];
		check[0] = check[1] ^ table[index*2+1];
		check[1] = table[index*2];
	}
	for (i=0; i<0x17; i++)
	{	buf[i] = encode(buf[i]);
	}
	memcpy(checksum, buf, 23);
}



u_char encode(u_char base)        /* 将一个字节的8位颠倒并取反*/
{
	u_char result = 0;
	int i;
	for (i=0; i<8; i++)
	{
		result <<= 1;
		result |= base&0x01;
		base >>= 1;
	}
	return ~result;
}


