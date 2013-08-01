/*
 ============================================================================
 Name        : ae.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */
#include "ae.h"


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CACERTF  HOME "demoCA/cacert.pem"
#define CAKEYF  HOME "demoCA/private/cakey.pem"
#define CLIENTCERTF  HOME "demoCA/newcerts/usercert2.pem"
#define CLIENTKEYF  HOME "userkey2.pem"
//#define PrivKey_PWD 111111

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

static int client_socket;

int connect_to_asu(char * asu_IP_addr)
{

    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;

    socklen_t server_addr_length;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K

    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

	printf("local test");

    //设置一个socket地址结构client_addr,代表客户端internet地址, 端口
    bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
    client_addr.sin_family = AF_INET;    //internet协议族
    client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY表示自动获取本机地址
    client_addr.sin_port = htons(0);    //0表示让系统自动分配一个空闲端口
    //创建用于internet的流协议(TCP)socket,用client_socket代表客户端socket
    client_socket = socket(AF_INET,SOCK_STREAM,0);
    if( client_socket < 0)
    {
        printf("Create Socket Failed!\n");
        return FAIL;
    }
    //把客户端的socket和客户端的socket地址结构联系起来
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
    {
        printf("Client Bind Port Failed!\n");
        return FAIL;
    }

    //设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if(inet_aton(asu_IP_addr,&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
    {
        printf("Server IP Address Error!\n");
        return FAIL;
    }
    server_addr.sin_port = htons(CHAT_SERVER_PORT);
    server_addr_length = sizeof(server_addr);


    setsockopt(client_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(client_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    //客户端向服务器发起连接,连接成功后client_socket代表了客户端和服务器的一个socket连接
    if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        printf("Can Not Connect To %s!\n",asu_IP_addr);
        return FAIL;
    }
    return SUCCEED;
}

BOOL getCertData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (userID == 0)
		//sprintf(certname, "./demoCA/cacert.pem");//./demoCA/
		sprintf(certname, "./cacert.pem");//./demoCA/
	else
		//sprintf(certname, "./demoCA/newcerts/usercert%d.pem", certnum);  //终端运行./client
		sprintf(certname, "./usercert%d.pem", userID);                //eclipse调试或运行

	printf("%s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	printf("cert's len is %d\n", *len);
	fclose(fp);
	printf("将证书保存到缓存buffer成功!\n");

	return TRUE;
}

EVP_PKEY * getprivkeyfromprivkeyfile(int userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	RSA* rsa;
	char keyname[40];

	if (userID == 0)
		sprintf(keyname, "./cakey.pem");//./demoCA/
	else
		sprintf(keyname, "./userkey%d.pem", userID);                //eclipse调试或运行
	fp = fopen(keyname, "r");

	printf("keyname = %s\n", keyname);
	if (fp == NULL)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", keyname);
		return NULL;
	}
	//printf("123456");

	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}
	//printf("654321");
	fclose(fp);

	// print
	//printf("Content of Private key PEM file\n");
	//RSA_print_fp(stdout, rsa, 0);
	printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free (rsa);
		return NULL;
	} else
	{
		RSA_free (rsa);
		return privKey;
	}
}

BOOL gen_sign(int user_ID, BYTE * input,int inputLength,BYTE * sign_value, unsigned int *sign_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, input, inputLength))	//计算签名（摘要）Update
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	* sign_len = temp_sign_len;

	printf("签名值是: \n");
	for (i = 0; i < * sign_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}






int par_certificate_auth_resp_packet(certificate_auth_requ * cert_auth_resp_buffer_recv)
{
	return SUCCEED;
}

//1) ProcessWAPIProtocolAuthActive
int fill_auth_active_packet(int user_ID,auth_active *auth_active_packet)
{
	//fill WAI packet head
	auth_active_packet->wai_packet_head.version = 1;
	auth_active_packet->wai_packet_head.type = 1;
	auth_active_packet->wai_packet_head.subtype = 3;
	auth_active_packet->wai_packet_head.reserved = 0;
	auth_active_packet->wai_packet_head.packetnumber = 1;
	auth_active_packet->wai_packet_head.fragmentnumber = 0;
	auth_active_packet->wai_packet_head.identify = 0;

	//file flag, auth identify, ae rand number
	auth_active_packet->flag = 0;
	memset((BYTE *)&auth_active_packet->authidentify, 0, sizeof(auth_active_packet->authidentify));
	memset((BYTE *)&auth_active_packet->aerandnum, 0, sizeof(auth_active_packet->aerandnum));

	//fill local ASU identity
	auth_active_packet->localasuidentity.identity_identify = 1; //X.509 cert
	
	BIO *b=NULL;    //bio\u63a5\u53e3
	X509 *local_cert=NULL;  //X509\u683c\u5f0f\u670d\u52a1\u7aef\u8bc1\u4e66
	X509_NAME *issuer_name=NULL;   //\u8bc1\u4e66\u9881\u53d1\u8005\u540d\u5b57
	X509_NAME *subject_name=NULL;   //\u8bc1\u4e66\u6240\u6709\u8005\u540d\u5b57
	char issuer_str[256] = {0};          //\u9881\u53d1\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	char subject_str[256] = {0};         //\u6240\u6709\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	long serialnum;
	int offset;
	//\u5c06PEM\u683c\u5f0f\u7684\u8bc1\u4e66\u5b58\u4e3aX509\u8bc1\u4e66\u683c\u5f0f
	char certname[40];

	SSLeay_add_all_algorithms();   //\u52a0\u8f7d\u76f8\u5173\u7b97\u6cd5
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中
	if (user_ID == 0)
		sprintf(certname, "./cacert.pem");//./demoCA/
	else
		sprintf(certname, "./usercert%d.pem", user_ID);                //eclipse调试或运行

	b=BIO_new_file(certname,"r");
	local_cert=PEM_read_bio_X509(b,NULL,NULL,NULL);
	BIO_free(b);
	if(local_cert==NULL)
	{
		printf("open local cert failed.\n");
		X509_free(local_cert);
		return FALSE;
	}
	//\u8bfb\u53d6\u9881\u53d1\u8005\u59d3\u540d
	issuer_name=X509_get_issuer_name(local_cert);
	X509_NAME_oneline(issuer_name,issuer_str,256);
	//\u8bfb\u53d6\u6240\u6709\u8005\u59d3\u540d
	subject_name=X509_get_subject_name(local_cert);
	X509_NAME_oneline(subject_name,subject_str,256);
	//\u8f93\u51fa\u8bc1\u4e66\u7684\u76f8\u5173\u53c2\u6570
	serialnum = ASN1_INTEGER_get(X509_get_serialNumber(local_cert));
	X509_free(local_cert);

	offset = 0;
	memcpy(auth_active_packet->localasuidentity.cer_der.data + offset, (BYTE*)subject_str, strlen(subject_str));
	offset += strlen(subject_str);
	memcpy(auth_active_packet->localasuidentity.cer_der.data + offset, (BYTE*)issuer_str, strlen(issuer_str));
	offset += strlen(issuer_str);
	memcpy(auth_active_packet->localasuidentity.cer_der.data + offset, (BYTE*)&serialnum, sizeof(serialnum)/sizeof(BYTE));
	offset += sizeof(serialnum);

	auth_active_packet->localasuidentity.identity_length = offset;

	//fill ecdh param
	int  oid_len;
	const  char  oid[]={"1.2.156.11235.1.1.2.1"}; 
	unsigned char  *buf; 

	oid_len=a2d_ASN1_OBJECT(NULL,0,oid,-1); 
	if (oid_len <= 0){
		printf("oid encode failed.\n");
		return FALSE;
	}
	buf=(unsigned char *)malloc(sizeof(unsigned char)*oid_len); 
	oid_len=a2d_ASN1_OBJECT(buf,oid_len,oid,-1); 

	auth_active_packet->ecdhparam.param_identify = 1;
	auth_active_packet->ecdhparam.param_length = oid_len;
	memcpy(auth_active_packet->ecdhparam.oid.oid_code, buf, oid_len);
	free(buf);

	//fill certificate
	auth_active_packet->certificatestaae.cer_identify = 1; //X.509 cert
	
	BYTE cert_buffer[5000];
	int cert_len = 0;

	// !!!!!!!!!!! bug !!!!!!!!!!!!
	if (!getCertData(user_ID, cert_buffer, &cert_len))    //先读取ASUE证书，"demoCA/newcerts/usercert2.pem"
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}
	
	auth_active_packet->certificatestaae.cer_length = cert_len;   //证书长度字段
	memcpy((auth_active_packet->certificatestaae.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));

	//fill signature
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	auth_active_packet->wai_packet_head.length = sizeof(auth_active);
	if(!gen_sign(user_ID, (BYTE *)auth_active_packet,(auth_active_packet->wai_packet_head.length-sizeof(auth_active_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	auth_active_packet->aesign.sign.length = sign_len;
	memcpy(auth_active_packet->aesign.sign.data,sign_value,sign_len);

	return SUCCEED;
	
}

int ProcessWAPIProtocolAuthActive()
{
	auth_active auth_active_packet;
	int user_ID = 2;

	memset((BYTE *)&auth_active_packet, 0, sizeof(auth_active_packet));
	if (fill_auth_active_packet(user_ID, &auth_active_packet)){
		printf("fill auth active packet failed!\n");
	}

	return SUCCEED;
	
}

//2) ProcessWAPIProtocolAccessAuthRequest
int ProcessWAPIProtocolAccessAuthRequest()
{
	return SUCCEED;
}

//3)
int gen_certificate_auth_requ_packet(int user_ID,certificate_auth_requ * send_buffer)
{
	BYTE buffer[5000];
	int len = 0;

	EVP_PKEY * privKey;

	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	send_buffer->wai_packet_head.version = 1;
	send_buffer->wai_packet_head.type = 1;
	send_buffer->wai_packet_head.subtype = 5;
	send_buffer->wai_packet_head.reserved = 0;
	send_buffer->wai_packet_head.packetnumber = 1;
	send_buffer->wai_packet_head.fragmentnumber = 0;
	send_buffer->wai_packet_head.identify = 0;

	bzero((send_buffer->addid.mac1),sizeof(send_buffer->addid.mac1));
	bzero((send_buffer->addid.mac2),sizeof(send_buffer->addid.mac1));

	bzero((send_buffer->aechallenge),sizeof(send_buffer->aechallenge));
	bzero((send_buffer->asuechallenge),sizeof(send_buffer->asuechallenge));

	if (!getCertData(2, buffer, &len))    //先读取ASUE证书，"demoCA/newcerts/usercert2.pem"
	{
		printf("将证书保存到缓存buffer失败!");
	}

	send_buffer->staasuecer.cer_identify = 1;   //证书标识字段，1-表示该字段的证书数据为X.509 v3 证书，2-表示该字段的证书数据为GBW 证书
	send_buffer->staasuecer.cer_length = len;   //证书长度字段
	memcpy((send_buffer->staasuecer.cer_X509),buffer,strlen((char*)buffer));

	if (!getCertData(2, buffer, &len))    //再读取AE证书，"demoCA/newcerts/usercert1.pem"
	{
		printf("将证书保存到缓存buffer失败!");
	}
	send_buffer->staaecer.cer_identify = 1;   //证书标识字段，1-表示该字段的证书数据为X.509 v3 证书，2-表示该字段的证书数据为GBW 证书
	send_buffer->staaecer.cer_length = len;   //证书长度字段
	memcpy(send_buffer->staaecer.cer_X509,buffer,strlen((char*)buffer));

/*
	int A = sizeof(send_buffer->wai_packet_head);
	int B = sizeof(send_buffer->addid);
	int C = sizeof(send_buffer->aechallenge);
	int D = sizeof(send_buffer->asuechallenge);
	int E = sizeof(send_buffer->staaecer);
	int F = sizeof(send_buffer->staasuecer);
	int G = sizeof(send_buffer->aesign);
*/
	send_buffer->wai_packet_head.length = sizeof(send_buffer->wai_packet_head)+sizeof(send_buffer->addid)
			+sizeof(send_buffer->aechallenge)+sizeof(send_buffer->asuechallenge)
			+sizeof(send_buffer->staaecer)+sizeof(send_buffer->staasuecer)
			+sizeof(send_buffer->aesign);

	//AE使用AE的私钥(userkey2.pem)来生成AE签名
	privKey = getprivkeyfromprivkeyfile(user_ID);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}
	if(!gen_sign(user_ID, (BYTE *)send_buffer,(send_buffer->wai_packet_head.length-sizeof(send_buffer->aesign)),sign_value, & sign_len,privKey))
	{
		printf("签名失败！");
	}

	send_buffer->aesign.sign.length = sign_len;
	memcpy(send_buffer->aesign.sign.data,sign_value,sign_len);

	return SUCCEED;
}

void ProcessWAPIProtocolCertAuthRequest()
{
	certificate_auth_requ cert_auth_requ_buffer_send;
	int user_ID = 2;
	bzero((BYTE *)&cert_auth_requ_buffer_send,sizeof(cert_auth_requ_buffer_send));
	//按照吕世超整理的认证协议中的【证书认证请求分组】来封装数据包
	gen_certificate_auth_requ_packet(user_ID,&cert_auth_requ_buffer_send);

	//客户端向服务器发送【证书认证请求分组】
	int sendlen = send(client_socket,(BYTE *)&cert_auth_requ_buffer_send,sizeof(cert_auth_requ_buffer_send),0);
	printf("--------------------------------------------------客户端发送%d数据--------------------\n",sendlen);

    if(sendlen <0)
    {
        printf("Socket Send Data Failed Or Closed\n");
        close(client_socket);
        exit(0);
    }
//    else
//    	return SUCCEED;
}

//4)
int ProcessWAPIProtocolCertAuthResp()
{
	certificate_auth_requ cert_auth_resp_buffer_recv;
	bzero((BYTE *)&cert_auth_resp_buffer_recv,sizeof(cert_auth_resp_buffer_recv));

	//客户端接收服务器发来的【证书认证响应分组】
	int length = recv(client_socket,(BYTE *)&cert_auth_resp_buffer_recv,sizeof(cert_auth_resp_buffer_recv),0);
	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
	}

	//客户端接收到服务器发来的【证书认证响应分组】后，按照协议规定来解析该数据包
	return par_certificate_auth_resp_packet(&cert_auth_resp_buffer_recv);

}

//5 ProcessWAPIProtocolAccessAuthResp
int ProcessWAPIProtocolAccessAuthResp()
{
	return SUCCEED;
}

void ProcessWAPIProtocol()
{
	//1) ProcessWAPIProtocolAuthActive
	printf("1) ProcessWAPIProtocolAuthActive: \n");
	ProcessWAPIProtocolAuthActive();
	

	//2) ProcessWAPIProtocolAccessAuthRequest



	//3) ProcessWAPIProtocolCertAuthRequest
	printf("3) ProcessWAPIProtocolCertAuthRequest: \n");
	ProcessWAPIProtocolCertAuthRequest();
	printf("客户端成功发送证书认证请求分组到服务器！\n");

	//4) ProcessWAPIProtocolCertAuthResp
	//recv_resp_from_server();

	//5 ProcessWAPIProtocolAccessAuthResp
}

int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();

    if (argc != 2)
    {
		printf("Usage: ./%s ServerIPAddress\n", argv[0]);
		exit(1);
	}

    connect_to_asu(argv[1]);

    ProcessWAPIProtocol();

	return 0;

}

