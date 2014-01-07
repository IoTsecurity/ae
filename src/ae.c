/*
 ============================================================================
 Name        : ae.c
 Author      : lsc yaoyao
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */
#include "ae.h"

#define CHAT_SERVER_PORT    (6666)
#define CHAT_LISTEN_PORT    (1111)


pid_t pid = -1;

//static char *ASUE_ip_addr;
static char *ASU_ip_addr;


static int annotation = 1;  //1-lvshichao,2-yaoyao

typedef struct user
{
    int user_ID;
    int client_socket;
    //client_socket==NOT_LOGIN,表示没有用户登录,
    //client_socket==NOT_IN_USE,表示没有用户注册,
}user;

//多线程共享user_table
static user user_table[USER_AMOUNT_MAX];
//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;

void init_user_table()
{
    int i=0;
    for(i=0;i<USER_AMOUNT_MAX;i++)
    {
        user_table[i].client_socket = NOT_IN_USE;
        user_table[i].user_ID = 255;
    }
}

int init_server_socket()
{
    struct sockaddr_in server_addr;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K
    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CHAT_LISTEN_PORT);

    int server_socket = socket(AF_INET,SOCK_STREAM,0);

    setsockopt(server_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(server_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    if( server_socket < 0)
    {
        perror("socket error!");
        exit(1);
    }

    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        perror("server bind error Failed!");
        exit(1);
    }

    if ( listen(server_socket, 5) )
    {
        printf("Server Listen Failed!");
        exit(1);
    }
    return server_socket;
}


int connect_to_asu()
{
	int client_socket;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    socklen_t server_addr_length;

    int nRecvBuf = 32*1024; //设置为32K
    int nSendBuf = 32*1024; //设置为32K

    //设置一个socket地址结构client_addr,代表客户端internet地址, 端口
    bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
    client_addr.sin_family = AF_INET;    //internet协议族
    client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY表示自动获取本机地址
    client_addr.sin_port = htons(0);    //0表示让系统自动分配一个空闲端口
    //创建用于internet的流协议(TCP)socket,用client_socket代表客户端socket

    if( (client_socket = socket(AF_INET,SOCK_STREAM,0)) < 0){
        printf("Create Socket Failed!\n");
        return FALSE;
    }
    //把客户端的socket和客户端的socket地址结构联系起来
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr))){
        printf("Client Bind Port Failed!\n");
        return FALSE;
    }

    //设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if(inet_aton(ASU_ip_addr,&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
    {
        printf("Server IP Address Error!\n");
        return FALSE;
    }
    server_addr.sin_port = htons(CHAT_SERVER_PORT);
    server_addr_length = sizeof(server_addr);

    setsockopt(client_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(client_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    //客户端向服务器发起连接,连接成功后client_socket代表了客户端和服务器的一个socket连接
    if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        printf("AE Can Not Connect To ASU %s!\n",ASU_ip_addr);
        return FALSE;
    }
    return client_socket;
	
}

int send_to_peer(int new_server_socket, BYTE *send_buffer, int send_len)
{

	int length = send(new_server_socket,send_buffer,send_len,0);
	printf("--- send %d bytes ---\n",length);

    if(length <0){
        printf("Socket Send Data Failed Or Closed\n");
        close(new_server_socket);
        return FALSE;
    }
	else
		return TRUE;
}


int recv_from_peer(int new_server_socket, BYTE *recv_buffer, int recv_len)
{
	int length = 0;
	length = recv(new_server_socket,recv_buffer, recv_len,MSG_WAITALL);//MSG_WAITALL
	
	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	}else if(length < recv_len)
	{
		printf("Receive data from server less than required, %d bytes.\n",length);
		return FALSE;
	}else if(length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	}
	else
	{
		printf("--- receive data succeed, %d bytes. ---\n",length);
		return TRUE;
	}

} 


void ProcessWAPIProtocol(int new_asue_socket)
{
	int user_ID = 2;
	int asu_socket;
	int auth_result=FALSE;

	EAP_auth_active eap_auth_active_packet;
	EAP_access_auth_requ eap_access_auth_requ_packet;
	EAP_access_auth_resp eap_access_auth_resp_packet;

	EAP_certificate_auth_requ eap_certificate_auth_requ_packet;//New code
	EAP_certificate_auth_resp eap_certificate_auth_resp_packet;//New code
	
	//1) ProcessWAPIProtocolAuthActive,send to asue
	if(annotation == 1)
		printf("\n***\n 1) 认证激活分组(网络硬盘录像机->摄像机): \n");
	else if(annotation == 2)
		printf("\n***\n 1) ProcessWAPIProtocolAuthActive: \n");
	//stop for keyboard
	//getchar();
	
	memset((BYTE *)&eap_auth_active_packet, 0, sizeof(eap_auth_active_packet));
	eap_auth_active_packet.eap_header.code=1;
	eap_auth_active_packet.eap_header.identifier=0;
	eap_auth_active_packet.eap_header.length=sizeof(eap_auth_active_packet);
	eap_auth_active_packet.eap_header.type=192;

	ProcessWAPIProtocolAuthActive(user_ID, &eap_auth_active_packet.auth_active_packet);
	send_to_peer(new_asue_socket, (BYTE *)&eap_auth_active_packet, sizeof(eap_auth_active_packet));

	//2) ProcessWAPIProtocolAccessAuthRequest, recv from asue
	if (annotation == 1)
		printf("\n***\n 2) 接入认证请求分组(摄像机->网络硬盘录像机，网络硬盘录像机处理该分组): \n");
	else if (annotation == 2)
		printf("\n***\n 2) HandleWAPIProtocolAccessAuthRequest: \n");
	if (annotation == 2)
		printf("recv auth active packet from ASUE...\n");

	memset((BYTE *)&eap_access_auth_requ_packet, 0, sizeof(EAP_access_auth_requ));
	recv_from_peer(new_asue_socket, (BYTE *)&eap_access_auth_requ_packet, sizeof(eap_access_auth_requ_packet));
	//verify access_auth_requ_packet
	HandleWAPIProtocolAccessAuthRequest(user_ID, &eap_auth_active_packet.auth_active_packet, &eap_access_auth_requ_packet.access_auth_requ_packet);

	//3) ProcessWAPIProtocolCertAuthRequest, send to asu
	if (annotation == 1)
		printf("\n***\n 网络硬盘录像机开始连接认证服务器: \n");
	else if (annotation == 2)
		printf("\n***\n Connect to asu.\n");
    asu_socket = connect_to_asu();
	if (annotation == 1)
		printf("\n***\n 网络硬盘录像机连接认证服务器成功！ \n");

	if (annotation == 1)
		printf("\n***\n 3) 证书认证请求分组(网络硬盘录像机->认证服务器): \n");
	else if (annotation == 2)
		printf("\n***\n 3) ProcessWAPIProtocolCertAuthRequest: \n");
	//stop for keyboard
	//getchar();
	
	memset((BYTE *)&eap_certificate_auth_requ_packet, 0, sizeof(eap_certificate_auth_requ_packet));//New code
	eap_certificate_auth_requ_packet.eap_header.code=1;//New code
	eap_certificate_auth_requ_packet.eap_header.identifier=2;//New code
	eap_certificate_auth_requ_packet.eap_header.length=sizeof(eap_certificate_auth_requ_packet);//New code
	eap_certificate_auth_requ_packet.eap_header.type=192;//New code
	

	ProcessWAPIProtocolCertAuthRequest(user_ID, &eap_access_auth_requ_packet.access_auth_requ_packet,&eap_certificate_auth_requ_packet.certificate_auth_requ_packet);
	send_to_peer(asu_socket,(BYTE *)&eap_certificate_auth_requ_packet, sizeof(eap_certificate_auth_requ_packet));

	//4) ProcessWAPIProtocolCertAuthResp, recv from asu
	if (annotation == 1)
		printf("\n***\n 4) 证书认证响应分组(认证服务器->网络硬盘录像机，认证服务器处理该分组): \n");
	else if (annotation == 2)
	{
		printf("\n***\n 4) HandleWAPIProtocolCertAuthResp: \n");
		printf("recv Cert Auth Resp packet from ASU...\n");
	}

	recv_from_peer(asu_socket, (BYTE *)&eap_certificate_auth_resp_packet, sizeof(eap_certificate_auth_resp_packet));
	memset((BYTE *)&eap_access_auth_resp_packet, 0, sizeof(eap_access_auth_resp_packet));

	//该函数的主要工作是查看证书验证结果，并填充接入认证响应分组
	auth_result = HandleProcessWAPIProtocolCertAuthResp(user_ID,&eap_certificate_auth_requ_packet.certificate_auth_requ_packet, &eap_certificate_auth_resp_packet.certificate_auth_resp_packet,&eap_access_auth_resp_packet.access_auth_resp_packet);

	//5) ProcessWAPIProtocolAccessAuthResp, send to asue
	if (annotation == 1)
		printf("\n***\n 5) 证书认证响应分组(认证服务器->网络硬盘录像机，网络硬盘录像机处理该分组): \n");
	else if (annotation == 2)
		printf("\n***\n 5) ProcessWAPIProtocolAccessAuthResp: \n");

	//stop for keyboard
	//getchar();


	eap_access_auth_resp_packet.eap_header.code=1;
	eap_access_auth_resp_packet.eap_header.identifier=1;
	eap_access_auth_resp_packet.eap_header.length=sizeof(eap_auth_active_packet);
	eap_access_auth_resp_packet.eap_header.type=192;

	ProcessWAPIProtocolAccessAuthResp(user_ID, &eap_access_auth_requ_packet.access_auth_requ_packet, &eap_access_auth_resp_packet.access_auth_resp_packet);
	send_to_peer(new_asue_socket, (BYTE *)&eap_access_auth_resp_packet, sizeof(eap_access_auth_resp_packet));

	// pid is global variable

	//run ffmpeg
	if(auth_result){
		if(pid < 0){
			char abuf[INET_ADDRSTRLEN];
			struct sockaddr_in asueaddr;
			socklen_t length = sizeof(asueaddr);
			getpeername(new_asue_socket, (struct sockaddr*) &asueaddr, &length);
			inet_ntop(AF_INET, &asueaddr.sin_addr, abuf, INET_ADDRSTRLEN);
			printf("\n");
			char *ffmpeg_prog_dir="";//"/home/yaoyao/ffmpeg_sources/ffmpeg/";
			char ffmpeg_cmd[256];
			//snprintf(ffmpeg_cmd,255,"%sffmpeg -debug ts -i rtsp://%s:8557/PSIA/Streaming/channels/2?videoCodecType=H.264 -vcodec copy -an http://localhost:8090/feed1.ffm",ffmpeg_prog_dir, abuf);
			snprintf(ffmpeg_cmd, 255,
			"%sffmpeg -debug ts -i rtsp://192.168.115.40:8557/PSIA/Streaming/channels/2?videoCodecType=H.264 -vcodec copy -an http://localhost:8090/feed1.ffm >/dev/null 2>/dev/null",
			ffmpeg_prog_dir);
			
			printf(ffmpeg_cmd);
			printf("\n");

			if((pid = fork()) < 0){
				perror("fork()");
			}else if(pid == 0){
				if(execl("/bin/sh", "sh", "-c", ffmpeg_cmd, (char *)0) < 0){
					perror("execl failed");
				}
				pid++;
			}else{}
		}
	}
	else{
		//int status;
		printf("kill %d\n",pid);
		kill(pid,SIGABRT);
		wait(NULL);
		pid++;
		printf("kill %d\n",pid);
		kill(pid,SIGABRT);
		wait(NULL);
		
		pid = -1;
	}

}
/*
void runffmpeg(pid_t *ffmpegpid, int res)
{

}
*/

void * serve_each_asue(void * new_server_socket_to_client)
{
	int new_asue_socket = (int)new_server_socket_to_client;

	printf("start serve asue...\n");
	
	ProcessWAPIProtocol(new_asue_socket);
	
	close(new_asue_socket);

	printf("pthread exit\n");
	pthread_exit(NULL);

}


void listen_from_asue()
{

	int threadnum = 1;
	init_user_table();
	pthread_mutex_init(&user_table_mutex, NULL);
	int server_socket = init_server_socket();

	pthread_t child_thread;
	pthread_attr_t child_thread_attr;
	pthread_attr_init(&child_thread_attr);
	pthread_attr_setdetachstate(&child_thread_attr, PTHREAD_CREATE_DETACHED);

    if (pthread_attr_init(&child_thread_attr) != 0)
    	perror("pthread_attr_init");

	pthread_attr_setdetachstate(&child_thread_attr,PTHREAD_CREATE_DETACHED);

	//  accept connection from each ASUE
	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);

		int new_asue_socket = accept(server_socket, (struct sockaddr*) &client_addr, &length);
		if (new_asue_socket < 0){
			perror("AE Accept Failed\n");
			//break;
		}

		printf("going to create thread %d ...\n", threadnum);
		if (pthread_create(&child_thread, &child_thread_attr, serve_each_asue,(void *) new_asue_socket) < 0)
		//if (pthread_create(&child_thread, NULL, serve_each_asue,(void *) new_asue_socket) < 0)
			perror("pthread_create Failed");
		//serve_each_asue((void *)new_asue_socket);

		threadnum++;
	}
}
/*
static void * threadFunc(void *arg)
{
 void *res;
 char *s = (char *) arg;
 pthread_t t = pthread_self();
 int relval = pthread_join(t, &res);

 if (relval) 
  perror("deadlock");
 printf("%s", arg);

  printf("return value is %d .....\n",relval);
  //return (void *) strlen(s);
  pthread_exit(&res);
}
*/


BOOL getCertRequData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certrequname[40];
	memset(certrequname, '\0', sizeof(certrequname));//初始化certname,以免后面写如乱码到文件中

	sprintf(certrequname, "./user/user_req.pem");


	printf("cert sign requ file name: %s\n", certrequname);

	fp = fopen(certrequname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert sign requ file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	printf("cert sign requ's length is %d\n", *len);
	fclose(fp);
	printf("将证书签发请求文件保存到缓存buffer成功!\n");

	return TRUE;
}

int fill_certificate_sign_requ_pcaket(int user_ID, char * username,BYTE *cert_request,int *cert_request_len,certificate_sign_requ *certificate_sign_requ_pcaket)
{
	memset((BYTE *)certificate_sign_requ_pcaket, 0, sizeof(certificate_sign_requ));

	printf("\n---用户生成证书签发请求文件过程begin---\n");

	user_gen_cert_request(user_ID, username);

	if(!(getCertRequData(user_ID, cert_request, cert_request_len)))
	{
		printf("将证书签发请求文件保存到缓存buffer失败!\n");
	}

	printf("---用户生成证书签发请求文件过程end---\n\n");

	memcpy(certificate_sign_requ_pcaket->certificate_sign_requ_buffer,cert_request,*cert_request_len);
	certificate_sign_requ_pcaket->certificate_sign_requ_buffer_len = *cert_request_len;

	//fill WAI packet head
	certificate_sign_requ_pcaket->wai_packet_head.version = 1;
	certificate_sign_requ_pcaket->wai_packet_head.type = 1;
	certificate_sign_requ_pcaket->wai_packet_head.subtype = REQUEST_CERTIFICATE;
	certificate_sign_requ_pcaket->wai_packet_head.reserved = 0;
	certificate_sign_requ_pcaket->wai_packet_head.length = sizeof(certificate_sign_requ);
	certificate_sign_requ_pcaket->wai_packet_head.packetnumber = 255;
	certificate_sign_requ_pcaket->wai_packet_head.fragmentnumber = 0;
	certificate_sign_requ_pcaket->wai_packet_head.identify = 0;

	return TRUE;
}

int Processgencertsignrequ(int user_ID, char * username,BYTE *cert_request,int *cert_request_len,certificate_sign_requ *certificate_sign_requ_pcaket)
{
	if (!fill_certificate_sign_requ_pcaket(user_ID, username,cert_request,cert_request_len,certificate_sign_requ_pcaket))
	{
		printf("fill cert sign requ packet failed!\n");
	}

	return TRUE;
}




int HandleCertSignResp(int user_ID, certificate_sign_resp *certificate_sign_resp_packet)
{
	if(!writeUserCertFile(2,certificate_sign_resp_packet->usercer.cer_X509,certificate_sign_resp_packet->usercer.cer_length))
	{
		printf("将用户的证书数据保存到PEM文件失败！\n");
	}

	return TRUE;
}

int main(int argc, char **argv)
{
	int asu_socket,user_ID;
	certificate_sign_requ certificate_sign_requ_pcaket;
	certificate_sign_resp certificate_sign_resp_packet;

	OpenSSL_add_all_algorithms();

    if (argc != 2)
    {
		printf("Usage: %s ASU_ip_addr\n", argv[0]);
		exit(1);
	}


	ASU_ip_addr = argv[1];


	//**************************************演示清单第一部分证书签发等操作 begin***************************************************
/*
	char *username = "20130811AE";
	user_ID = 2;
	BYTE cert_request[5000];
	int cert_request_len=0;

	Processgencertsignrequ(user_ID,username,cert_request,&cert_request_len,&certificate_sign_requ_pcaket);

    asu_socket = connect_to_asu();
	send_to_peer(asu_socket,(BYTE *)&certificate_sign_requ_pcaket, sizeof(certificate_sign_requ_pcaket));

	recv_from_peer(asu_socket,(BYTE *)&certificate_sign_resp_packet, sizeof(certificate_sign_resp_packet));
	HandleCertSignResp(user_ID, &certificate_sign_resp_packet);
*/
	//**************************************演示清单第一部分离线证书签发等操作 end********************************************************
/*
	printf("test pthread\n");
	
	 pthread_t t1;
	 void *res;
	 int ret;

	 ret = pthread_create(&t1, NULL, threadFunc, "Hello world\n");
	 if (ret != 0)
	    perror("pthread_create");

	 printf("Message from main()\n");
	 printf("res = %d\n",(int)res);
	 
*/
	printf("listen from asue.\n");
	listen_from_asue();

	return 0;

}

