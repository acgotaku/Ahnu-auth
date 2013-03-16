#include <stdio.h>		//for perror
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <arpa/inet.h>  //for inet_ntoa
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <iconv.h>
#include <locale.h>
#include <time.h>
#include <getopt.h>

struct usrinfoSet {
	char *usr;
	char *pw;
	char dev[0xc];
	char ip[0x10];
	char mac[0x8];
};

struct hash{
	char *filePath;
	char *randnum;
	char *programName;
	char service[0xc];
	char host[0x10];
	int mode;
	time_t loginTime;
	bool leave;
	bool selectServerType;
	bool autoFindServer;
	bool recvSuccess;
};

struct infoset  {
	struct sockaddr_in * psv;
	struct usrinfoSet * pui;
	struct hash *phs;
};
