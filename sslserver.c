#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WINDOWS	/*Microsoft windows system*/
#include <winsock.h>
#define	socklen_t int
#define bzero(buf, len) memset(buf, 0, len)
#else			/*UNIX*/
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#define closesocket close
#endif


#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024

int main(int argc, char **argv)
{
	int sockfd, new_fd;
	socklen_t len;
	struct sockaddr_in my_addr, their_addr;
	unsigned int myport;
	char buf[MAXBUF + 1];
	SSL_CTX *ctx;

	if (argc != 4) {
		printf("Usage: sslserver port certfile privkeyfile\n");
		exit(1);
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

#ifdef _WINDOWS
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);
#endif
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}
	else
		printf("socket created\n");

	myport = atoi(argv[1]);
	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(myport);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
		== -1) {
		perror("bind");
		exit(1);
	}
	else
		printf("binded\n");

	if (listen(sockfd, 2) == -1) {
		perror("listen");
		exit(1);
	}
	else
		printf("begin listen\n");

	while (1) {
		SSL *ssl;
		len = sizeof(struct sockaddr);
		if ((new_fd =
			accept(sockfd, (struct sockaddr *) &their_addr,
				&len)) == -1) {
			perror("accept");
			exit(errno);
		}
		else
			printf("server: got connection from %s, port %d, socket %d\n",
				inet_ntoa(their_addr.sin_addr),
				ntohs(their_addr.sin_port), new_fd);


		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, new_fd);
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			close(new_fd);
			break;
		}

		bzero(buf, MAXBUF + 1);
		strcpy(buf, "server->client");
		len = SSL_write(ssl, buf, strlen(buf));

		if (len <= 0) {
			printf
			("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
				buf, errno, strerror(errno));
		}
		else
			printf("消息'%s'发送成功，共发送了%d个字节！\n",
				buf, len);

		bzero(buf, MAXBUF + 1);
		len = SSL_read(ssl, buf, MAXBUF);
		if (len > 0)
			printf("接收消息成功:'%s'，共%d个字节的数据\n",
				buf, len);
		else
			printf
			("消息接收失败！错误代码是%d，错误信息是'%s'\n",
				errno, strerror(errno));

		SSL_shutdown(ssl);
		SSL_free(ssl);
		closesocket(new_fd);
	}

	SSL_CTX_free(ctx);
	closesocket(sockfd);

	return 0;
}
