/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* 子函数声明 */
int Authentication(const char *UserName, const char *Password, const char *DeviceName);


/**
 * 函数：main()
 *
 * 检查程序的执行权限，检查命令行参数格式。
 * 允许的调用格式包括：
 * 	njit-client  username  password
 * 	njit-client  username  password  eth0
 * 	njit-client  username  password  eth1
 * 若没有从命令行指定网卡，则默认将使用eth0
 */
int main(int argc, char *argv[])
{
	char *UserName;
	char *Password;
	char *DeviceName;
	printf("\n***************************************************************\n\n");
	printf("SCUTclient is based on njit8021xclient which is made by liuqun.\n");
	printf("Welcome to report bugs at Router of SCUT QQ group 262939451.\n\n");
	printf("					------Forward @SCUT\n");
	printf("\n***************************************************************\n");
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "Sorry,it is unroot.\n");
		exit(-1);
	}

	/* 检查命令行参数格式 */
	if (argc<2 || argc>4) {
		fprintf(stderr, "Command is Illegal\n");
		fprintf(stderr,	"    %s username\n", argv[0]);
		fprintf(stderr,	"    %s username password \n", argv[0]);
		fprintf(stderr,	"    %s username password Interface_Of_Wan\n", argv[0]);

		exit(-1);
	}
	if (argc == 4) {
		DeviceName = argv[3]; // 允许从命令行指定设备名
		UserName = argv[1];
		Password = argv[2];
	}
	if (argc == 3 || argc == 2) {
		UserName = argv[1];
		if (argc == 2){
			Password = UserName;// 用户名和密码相同
		}
		else {
			Password = argv[2];
		}
		FILE   *stream;
		char   buf[20]={0};
		char   tmp[20]={0};
		int    count = 0;
		//memset( buf, '/0', sizeof(buf) );
		stream = popen( "uci get network.wan.ifname", "r" );
		count = fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
		DeviceName=tmp;
		memcpy(DeviceName, buf , count-1);
		pclose( stream );
	}



	/* 调用子函数完成802.1X认证 */
	Authentication(UserName, Password, DeviceName);

	return (0);
}

