/*
 File:
    srun.c
    url.c
    url.h
 How To Compile it :
    gcc srun.c url.c -o srun
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned char uchar;

int keep_alive();
int getTimeStamp();
void post_login(uchar*, uchar*, uchar*);
int get_result(int);
int handle_msg(char*);
char *php_url_encode(char const *s, int len, int *new_length);

long syncTime=0; // delta = serverTime - localTime;
uchar nowKey[64]; // about nowtime;
uchar enc_mac[64];
uchar enc_pwd[64];
uchar username[64];
uchar password[64];
uchar macaddr[64];
long long lda[5];//after success login.


char* urlencode(uchar *s)
{
	int nlen;
	char *result=php_url_encode(s, strlen(s), &nlen);
	printf("[debug]url_encode %s >> %s\n", s, result);
	return result;
}

void set_time (long servertime)
{
	printf("\nSet Time...\n");
	printf("\tServer Time: %ld\n\tLocal  Time: %ld\n", servertime, (long)time(NULL));
	syncTime = servertime - (int)time(NULL);
	printf("\tDELTA  Time= %ld\n", syncTime);
}
void update_key()
{
	int i;
	char now[16];
	sprintf( now, "%ld", (long)((long)time(NULL) + syncTime)/60 );
	//printf("now=%s %ld\n", now, (long)time(NULL));
	int ns=strlen(now);
	for (i=0;i<64;i++)
		nowKey[i]=now[ns-i%ns-1];

	//debug:
/*
	uchar tmp[8]={'2', '2', '8', '4', '4', '4', '9', '7'};// to be var 'now'
	for (i=0;i<64;i++)
		nowKey[i]=tmp[7-i%8];
*/
}
void generate(uchar* input, int len, uchar *result)
{
	uchar num[64];
	memcpy(num, input, len+1);
	//printf("]]%s %d %s\n", num,strlen(num),result);
	int i;
	uchar low,high;
	update_key();
	//first: key xor number
	for (i=0;i<len;i++)
		num[i] = nowKey[i]^num[i];
	//second: +0x63 +0x36 
	for (i=0;i<len;i++)
	{
		low = num[i]&0x0f;
		high = (num[i]>>4)&0x0f;
		//printf("%02x--%d %d",num[i], high,low);
		if (!(i%2))
		{
			result[i*2] = low+0x36;
			result[i*2+1] = high+0x63;
		}
		else
		{
			result[i*2] = high+0x63;
			result[i*2+1] = low+0x36;
		}
		//printf(">>%02x %02x\n", result[i*2],result[i*2+1]);
	}
	result[len*2]='\0';

	//printf(">>>>%s\n", result);
}

void generate_password()
{
	generate(password, strlen(password), enc_pwd);
}
void generate_macaddr()
{
	generate(macaddr, strlen(macaddr), enc_mac);
}
int main (int argc, char* argv[])
{
    int tmp;
	if (argc != 4)
	{
		printf("  Using: %s username password macaddr\n", argv[0]);
		printf("Example: %s vrqq 123456 00:11:22:aa:bb:cc\n", argv[0]);
		return 0;
	}
	if (strlen(argv[3])!=17)
	{
		printf("Invalid MAC Address.\n");
		return 0;
	}
	memcpy(username, argv[1], strlen(argv[1])+1);
	memcpy(password, argv[2], strlen(argv[2])+1);
	memcpy(macaddr,  argv[3], strlen(argv[3])+1);
	printf("Starting Authorication...\nUsername = %s\nPassword = %s\nMacaddr  = %s\n",username,password,macaddr);

	printf("[Message] Update TimeStamp...\n");
	if (!getTimeStamp())
		return 0;

	printf("[Message] Login......\n");
	generate_password();
	generate_macaddr();
    //	post_login(username, enc_pwd, enc_mac);
    while (1)
    {
        post_login(username, enc_pwd, enc_mac);
        tmp = get_result(0);
        if ( tmp>=0 )
        {
            printf("[Message] Login Success.\nProgram Exit...");
/*
            while( keep_alive() )
                //sleep 5min
                system("sleep 250s");//for linux.
 */
            return 0;
        }
        else if (tmp == -4)
        {
            printf("Waiting for 5secs...\n");
            system("sleep 5s");
        }
        else
        {
            printf("[Message] Login Failure.\n");
            return 0;
        }
    }
	return 0;
}

int keep_alive()
{
	printf("\nSend keep_alive package.\n");
	char cmd[256];
	sprintf(cmd, "wget -O \"/tmp/web-keeplive.html\" --post-data=\"uid=%s\" \"http://self.ncepu.edu.cn/cgi-bin/keeplive\"",urlencode(username));
	printf("[DEBUG] RUN:\n  %s\n", cmd);
	system(cmd);
    if (get_result(1) < 0)
    {
        return 0; // Failure.
    }
    return 1;
}
int getTimeStamp()// Send a wrong password to get new timestamp.
{
	memcpy(enc_pwd, password, strlen(password));
	generate_macaddr();
	//printf(">>debug>>%s %s %s\n", username, enc_pwd, enc_mac);
	post_login(username, enc_pwd, enc_mac);
	if (get_result(0) == -1)
		return 1;
	printf("Can't get new TimeStamp.\nProgram Exit.\n\n");
	return 0;
}
void post_login(uchar* user, uchar* pwd, uchar* mac)
{
	printf("\nPost Login...\n");
	char pst[256];
	sprintf(pst, "username=%s&password=%s&drop=0&type=10&n=100&mac=%s&ip=169322688",urlencode(user),urlencode(pwd),urlencode(mac));
	char cmd[256];
	sprintf(cmd, "wget -O \"/tmp/internet.html\" --post-data=\"%s\" \"http://self.ncepu.edu.cn/cgi-bin/do_login\"",pst);
	printf("[DEBUG] RUN:\n  %s\n", cmd);
	system(cmd);
}
int get_result(int fid)
{
	printf("[DEBUG] Read Result.\n");
	FILE *ff;
    if (fid ==0)
        ff = fopen("/tmp/internet.html","r");
    else
        ff = fopen("/tmp/web-keeplive.html","r");
	if (ff == NULL)
	{
		printf("\tInternal Error. No Result was found.\n");
		return -9;
	}
	char result[512];
	fscanf(ff, "%s",result);
    fclose(ff);
	return handle_msg(result);
}
int handle_msg(char* msg)
{
	long tmp;
	printf("Message: %s\n",msg);
	//pwd:
	if (strstr(msg,"password_error"))
	{
		sscanf(msg,"password_error@%ld",&tmp);
		set_time(tmp);
		return -1;
	}
	//mac:
	if(strstr(msg,"mac_error"))
	{
		printf("Mac Addr error.\n");
		return -2;
	}
    if(strstr(msg,"ip_exist_error"))
    {
        printf("IP Existed...Reconnecting...\n");
        return -4;
    }
	//other error:
	if(strstr(msg,"error"))
	{
		printf("%s\n", msg);
		return -3;
	}
	//login success:
	printf("Login Success.\n");
	printf("%s\n", msg);
	sscanf(msg,"%lld,%lld,%lld,%lld,%lld",&lda[0],&lda[1],&lda[2],&lda[3],&lda[4],&lda[5]); //for example:13490492280620,322879779999055873,0,0,0
    printf("Your userID is : %lld",lda[0]);
	return 0;
}
