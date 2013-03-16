#include "md5.h"
#include "aecium.h"
#define SERVERPORT 3848
#define VERSION "0.0.1"
#define INFORMATION_FILE "host=%s\nservice=%s\ninterface=%s\nrandnum=%s\ntime=%lu" /* Information mode in file ~/.PROGRAM_NAME, such as "~/.aecium". */
#define PROGRAM_NAME "aecium"

static char *programMode;

void usage(int status)
{
	if ( status != EXIT_SUCCESS) {
		fprintf(stderr, "Try \'%s --help for more information.\n", programMode);
	} else {
		puts("USAGE");
		fprintf(stdout, "\t%s -u Username -p Password [-h Host] [-d Device] [-s]\n", programMode);
		fprintf(stdout, "\t%s -q | -e | -l | -v | --help\n", programMode);
		puts("OPTIONS");
		puts("\t-u | --username\n\t\tUser name");
		puts("\t-p | --password\n\t\tUser password");
		puts("\t-h | --host\n\t\tServer host IP address");
		puts("\t-d | --device\n\t\tNetwork card interface");
		puts("\t-s | --service\n\t\tSelect service");
		puts("\t-v | --version\n\t\tShow procedure version");
		puts("\t-q | --quit\n\t-e | --exit\n\t-l | --leave\n\t\tQuit procedure, leave Internet");
		puts("\t     --help\n\t\tShow usage");
	}

	exit(status);
}

static inline void errorExit(const char *error)
{
	fputs(error, stderr);
	exit(EXIT_SUCCESS);
}

static void getProgramName(struct hash *phs)
{
	if ( programMode ) {
		phs -> programName = strrchr(programMode, '/');

		if ( phs -> programName ) {
			++ phs -> programName;
		} else {
			phs -> programName = programMode;
		}
	}
}

static void getFilePath(struct hash *phs)
{
	if ( phs -> programName ) {
		char *homeDir = getenv("HOME");

		phs -> filePath = (char *)calloc(strlen(homeDir) + strlen(phs -> programName) + 0x3, sizeof(char));
		strcpy(phs -> filePath, homeDir);
		strcat(phs -> filePath, "/.");
		strcat(phs -> filePath, phs -> programName);
	}
}

static void freeAllocateMemory(struct infoset *pinfo)
{
	struct hash *phs = pinfo -> phs;

	if ( phs -> filePath ) {
		free(phs -> filePath);
		phs -> filePath = NULL;
	}

	if ( phs -> randnum ) {
		free(phs -> randnum);
		phs -> randnum = NULL;
	}
}

static int getOtherPid(const char * const restrict programName)
{
	FILE *fd;
	int pid = 0;
	char *command = NULL;

	command = (char *)calloc(strlen(programName) + 0x10, sizeof(char));

	strcpy(command, "ps | grep ");
	strcat(command, programName);
	printf("programName->%s",programName);
	if ( (fd = popen(command, "r")) == NULL ) {
		perror("popen");
		exit(EXIT_FAILURE);
	} else {	
		free(command);
		command = NULL;
	}
		char temp[256];
		strcpy(temp,"./");
		strcat(temp,programName);
		printf("%s\n",temp);
	for( char buf[0x100] = {0x0}; fgets(buf, 0x100, fd) && pid == 0x0; ) {
		printf("buf-->%s",buf);
		if ( strstr(buf, temp) ) {
			if ( getpid() == (pid = atoi(buf)) ) {
				pid = 0x0;
			}
		}
	}

	pclose(fd);
	printf("Pid__>%d",pid);
	
	return pid;
}

static void checkArgument(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct hash *phs = pinfo -> phs;

	int c, index = 0;
	struct option options[] = {
		{"username", 1, NULL, 'u'},
		{"password", 1, NULL, 'p'},
		{"host", 1, NULL, 'h'},
		{"device", 1, NULL, 'd'},
		{"service", 0, NULL, 's'},
		{"version", 0, NULL, 'v'},
		{"help", 0, NULL, 0},
		{"quit", 0, NULL, 'q'},
		{"exit", 0, NULL, 'e'},
		{"leave", 0, NULL, 'l'},
		{NULL, 0, NULL, 0}
	};

	while ( (c = getopt_long(argc, argv, "u:p:h:d:svqel", options, &index)) != -1 ) {
		switch ( c ) {
			case 'u':
				pui -> usr = optarg;
				break;
			case 'p':
				pui -> pw = optarg;
				break;
			case 'h':
				strcpy(phs -> host, optarg);
				break;
			case 'd':
				strcpy(pui -> dev, optarg);
				break;
			case 's':
				phs -> selectServerType = true;
				break;
			case 'q':
			case 'e':
			case 'l':
				phs -> leave = true;
				break;	
			case 'v':
				puts(VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 0:
				usage(EXIT_SUCCESS);
				break;
			case '?':
			default:
				usage(EXIT_FAILURE);
				break;
		}
	}
}

static void accessInfoFromFile(struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct hash *phs = pinfo -> phs;

	FILE *fd;

	if ( (fd = fopen(phs -> filePath, "r")) == NULL ) {
		printf("fopen(%s, \"r\"): %s\n", phs -> filePath, strerror(errno));
		usage(EXIT_FAILURE);
	}
  {
	unsigned int hostlen = strlen(phs -> host), devlen = strlen(pui -> dev), servicelen = strlen(phs -> service);
	bool infoIncomplete;

	for ( char buf[0x50] = {0x0}, *pos; (infoIncomplete = !(hostlen && devlen && servicelen)) && fgets(buf, 0x50, fd); ) {

		if ( buf[strlen(buf) - 1] == '\n' ) {
			buf[strlen(buf) - 1] = '\0';
		}

		if ( devlen == 0x0 && (pos = strstr(buf, "interface=")) ) {
			strcpy(pui -> dev, pos + 0xa);
			devlen = strlen(pui -> dev);
			continue;
		}

		if ( hostlen == 0x0 && (pos = strstr(buf, "host=")) ) {
			strcpy(phs -> host, pos + 0x5);
			hostlen = strlen(phs -> host);
			continue;
		}

		if ( servicelen == 0x0 && (pos = strstr(buf, "service=")) ) {
			strcpy(phs -> service, pos + 0x8);
			servicelen = strlen(phs -> service);
			continue;
		}
	}

	if ( infoIncomplete ) {
		fprintf(stderr, "Incomplete information for accessing Internet, check the file \"%s%s\".\n", "~/.", phs -> programName);
		usage(EXIT_FAILURE);
	}
  }

	fclose(fd);
}

static void leaveInfoFromFile(struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct hash *phs = pinfo -> phs;
	FILE *fd;

	if ( (fd = fopen(phs -> filePath, "r")) == NULL ) {
		printf("fopen(%s, \"r\"): %s\n", phs -> filePath, strerror(errno));
		usage(EXIT_FAILURE);
	}

  {
	time_t *loginTime = &(phs -> loginTime);
	unsigned int hostlen = strlen(phs -> host), devlen = strlen(pui -> dev), randnumlen = 0;
	bool infoIncomplete;

	for ( char buf[0x50] = {0x0}, *pos; (infoIncomplete = !(hostlen && devlen && randnumlen && *loginTime)) && fgets(buf, 0x50, fd); ) {

		if ( buf[strlen(buf) - 1] == '\n' ) {
			buf[strlen(buf) - 1] = '\0';
		}

		if ( hostlen == 0x0 && (pos = strstr(buf, "host=")) ) {
			strcpy(phs -> host, pos + 0x5);
			hostlen = strlen(phs -> host);
			continue;
		}

		if ( devlen == 0x0 && (pos = strstr(buf, "interface=")) ) {
			strcpy(pui -> dev, pos + 0xa);
			devlen = strlen(pui -> dev);
			continue;
		}

		if ( randnumlen == 0x0 && (pos = strstr(buf, "randnum=")) ) {
			phs -> randnum = (char *)calloc(strlen(pos + 0x8) + 0x1, sizeof(char));
			strcpy(phs -> randnum, pos + 0x8);
			randnumlen = strlen(phs -> randnum);
			continue;
		}

		if ( *loginTime == 0x0 && (pos = strstr(buf, "time=")) ) {
			*loginTime = (time_t)atol(pos + 0x5);
			continue;
		}
	}

	if ( infoIncomplete ) {
		fprintf(stderr, "Incomplete information for leaving Internet, check the file \"%s%s\".\n", "~/.", phs -> programName);
		exit(EXIT_FAILURE);
	}
  }

	fclose(fd);
}

static void getInfo(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct hash *phs = pinfo -> phs;

	checkArgument(argc, argv, pinfo);
	getFilePath(phs);

	if ( phs -> leave ) {
		phs -> mode = 0x5;
		leaveInfoFromFile(pinfo);
	} else {
		phs -> mode = 0x1;
		if ( !( pui -> usr && pui -> pw ) ) {
			fputs("Please input username and password!\n", stderr);
			usage(EXIT_FAILURE);
		}

		if ( phs -> selectServerType ) {
			char c = 0x0;

			puts("Select service:");
			puts("\t1. int");
			fprintf(stdout, "please select(type \'e\' to exit):");

			if ( c = getchar(), fflush(stdin), c == 'e') {
				exit(EXIT_SUCCESS);
			} else if ( c == '1' ) {
				strcpy(phs -> service, "int");
			} else {
				fputs("Invalid service option!\n", stderr);
				exit(EXIT_FAILURE);
			}
		}

		if ( !( strlen(phs -> host) && strlen(pui -> dev) && strlen(phs -> service) ) ) {
			accessInfoFromFile(pinfo);
		}
	}
}

static void getAddr(int sockfd, struct usrinfoSet *pui)
{
	struct ifreq addr;

	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, pui -> dev);

	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	strcpy(pui -> ip, inet_ntoa(((struct sockaddr_in *)&addr.ifr_addr) -> sin_addr));

	memset(&addr, 0, sizeof addr);
	strcpy(addr.ifr_name, (*pui).dev);

	if(ioctl(sockfd, SIOCGIFHWADDR, (char *)&addr) == -1) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	memcpy(pui -> mac, addr.ifr_hwaddr.sa_data, 0x6);
}

static void infoInit(int argc, char **argv, struct infoset * const pinfo)
{
	struct hash *phs = pinfo -> phs;

	programMode = argv[0];

	getProgramName(phs);
	getInfo(argc, argv, pinfo);
}

static void serverInit(struct infoset * const pinfo)
{
	struct sockaddr_in *psv = pinfo -> psv;
	struct hash *phs = pinfo -> phs;

	memset(psv, 0x0, sizeof(struct sockaddr_in));

	psv -> sin_family = AF_INET;
	psv -> sin_port = htons(SERVERPORT);
	psv -> sin_addr.s_addr = inet_addr(phs -> host);
}

static void pktEncrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		for (int i = 0; i < len; i++) {
			char c, tmp, dest;
			c = s[i];
			dest = (c & 0x1) << 7;

			tmp = (c & 0x2) >> 1;
			dest = tmp | dest;

			tmp = (c & 0x4) << 2;
			dest = tmp | dest;

			tmp = (c & 0x8) << 2;
			dest = tmp | dest;

			tmp = (c & 0x10) << 2;
			dest = tmp | dest;

			tmp = (c & 0x20) >> 2;
			dest = tmp | dest;

			tmp = (c & 0x40) >> 4;
			dest = tmp | dest;

			tmp = (c & 0x80) >> 6;
			dest = tmp | dest;

			s[i] = dest;
		}
	}
}

static void pktDecrypt(char *s, int len)
{
	if ( s != NULL && len > 0x0 ) {
		for (int i = 0; i < len; i++) {
			char c, tmp ,dest;

			c = s[i];

			dest = (c & 0x1) << 1;

			tmp = (c & 0x2) << 6;
			dest = tmp | dest;

			tmp = (c & 0x4) << 4;
			dest = tmp | dest;

			tmp = (c & 0x8) << 2;
			dest = tmp | dest;

			tmp = (c & 0x10) >> 2;
			dest = tmp | dest;

			tmp = (c & 0x20) >> 2;
			dest = tmp | dest;

			tmp = (c & 0x40) >> 2;
			dest = tmp | dest;

			tmp = (c & 0x80) >> 7;
			dest = tmp | dest;

			s[i] = dest;
		}
	}
}

static void sendRequestPacket(int sockfd, const struct infoset *pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct hash *phs = pinfo -> phs;
	int mode = phs -> mode;

	char *pkt, *ppkt;

	if ( mode == 0x1 ) {
		int usrlen = strlen(pui -> usr), pwlen = strlen(pui -> pw), iplen = strlen(pui -> ip), maclen = 0x6, servicelen = strlen(phs -> service);
		int sendbytes = usrlen + pwlen + iplen + maclen + servicelen + 0x1c;

		pkt = (char *)calloc(sendbytes, sizeof(char));
		ppkt = pkt;

		*ppkt++ = mode;
		*ppkt++ = sendbytes;
		ppkt += 0x10;

		*ppkt++ = 0x1;
		*ppkt++ = usrlen + 0x2;
		memcpy(ppkt, pui -> usr, usrlen);
		ppkt += usrlen;

		*ppkt++ = 0x2;
		*ppkt++ = pwlen + 0x2;
		memcpy(ppkt, pui -> pw, pwlen);
		ppkt += pwlen;

		*ppkt++ = 0x7;
		*ppkt++ = maclen + 0x2;
		memcpy(ppkt, pui -> mac, maclen);
		ppkt += maclen;

		*ppkt++ = 0x9;
		*ppkt++ = iplen + 0x2;
		memcpy(ppkt, pui -> ip, iplen);
		ppkt += iplen;

		*ppkt++ = 0xa;
		*ppkt++ = servicelen + 0x2;
		memcpy(ppkt, phs -> service, servicelen);
		ppkt += servicelen;
	} else if ( mode == 0x3 || mode == 0x5 ) {
		int maclen = 0x6, iplen = strlen(pui -> ip), randnumlen = strlen(phs -> randnum);
		int sendbytes = maclen + iplen + randnumlen + 0x18;

		pkt = (char *)calloc(sendbytes, sizeof(char));
		ppkt = pkt;

		*ppkt++ = mode;
		*ppkt++ = sendbytes;
		ppkt += 0x10;

		*ppkt++ = 0x7;
		*ppkt++ = maclen + 2;
		memcpy(ppkt, pui -> mac, maclen);
		ppkt += maclen;

		*ppkt++ = 0x8;
		*ppkt++ = randnumlen + 2;
		memcpy(ppkt, phs -> randnum, randnumlen);
		ppkt += randnumlen;

		*ppkt++ = 0x9;
		*ppkt++ = iplen + 2;
		memcpy(ppkt, pui -> ip, iplen);
		ppkt += iplen;
	} else if ( mode == 0x7 ) {
		int maclen = 0x6;
		int sendbytes = maclen + 0x14;

		pkt = (char *)calloc(sendbytes, sizeof(char));
		ppkt = pkt;

		*ppkt++ = mode;
		*ppkt++ = sendbytes;
		ppkt += 0x10;

		*ppkt++ = 0x7;
		*ppkt++ = maclen + 0x2;
		memcpy(ppkt, pui -> mac, maclen);
		ppkt += maclen;
	} else {
		errorExit("Invalid structure!\n");
	}

	MD5Calc((unsigned char *)pkt + 2, (unsigned char *)pkt, pkt[1]);
	pktEncrypt(pkt, pkt[1]);

	if ( sendto(sockfd, pkt, (size_t)(ppkt - pkt), 0, (struct sockaddr *)(pinfo -> psv), sizeof (struct sockaddr)) == -1 ) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
	puts("send success");
	free(pkt);
}

static void checkPacketMD5(char *pkt)
{
	char md5[0x10] = {0x0};
	int  md5len = 0x10;

	memcpy(md5, pkt + 2, md5len);
	memset(pkt + 2, 0x0, md5len);

	MD5Calc((unsigned char *)pkt + 0x2, (unsigned char *)pkt, pkt[1]);

	if ( memcmp(md5, pkt + 2, md5len) ) {
		errorExit("Packet MD5 value invalid!\n");
	}
}
static bool checkResponsePacket(char * const pkt, int pktsize)
{
	int pktlen = pkt[1];

	if ( pktlen <= pktsize && pktlen > 0x11) {
		checkPacketMD5(pkt);

		if ( pkt[0] > 0x9 ) {
			exit(EXIT_SUCCESS);
		}

	} else {
		errorExit("Invalid package size!\n");
	}

	return (bool)pkt[0x14];
}

static void outputUnderCurrentEncoding(char * const src)
{
	

	puts(src);
}

static void messageFromPacket(const char * const pkt, struct hash * phs)
{
	const char * ppkt = pkt;
	ppkt += 0x14;
	ppkt += *(ppkt - 1) - 0x2;

	if ( *ppkt == 0x8 ) {
		++ ppkt;

		if ( phs -> mode == 0x1 && phs -> recvSuccess ) {
			phs -> randnum = (char *)calloc(*ppkt + 1, sizeof(char));
			strncpy(phs -> randnum, ppkt + 1, *ppkt);
		}

		ppkt += *ppkt + 1;

		if ( ppkt - pkt < pkt[1] ) {
			if ( phs -> mode == 0x1 || phs -> recvSuccess == false ) {
				if ( phs -> recvSuccess ) {
					ppkt += 0x6;
				}

				if ( *ppkt == 0xb ) {
					char * message = (char *)calloc(*(++ ppkt) + 1, sizeof(char));

					strncpy(message, ppkt + 1, *ppkt);
					outputUnderCurrentEncoding(message);
					free(message);
				} else {
					errorExit("Invalid package, or packet mode has been changed!\n");
				}
			}
		}
	} else {
		errorExit("Invalid package, or packet mode has been changed!\n");
	}
}

static bool handleResponsePacket(char * const pkt, int pktsize)
{
	pktDecrypt(pkt, pktsize);
	return checkResponsePacket(pkt, pktsize);
}

static void controlPacket(int sockfd, struct infoset * pinfo)
{
	struct hash *phs = pinfo -> phs;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct timeval timeout;
	fd_set rfds;

	timeout.tv_sec = 0x1e;
	timeout.tv_usec = 0x0;

	sendRequestPacket(sockfd, pinfo);

	for ( int timeHasRepeat = 0, timeToRepeat = 0x3, retval; timeToRepeat > timeHasRepeat; ) {
		int pktsize = 0x100;
		char * const pkt = (char *)calloc(pktsize, sizeof(char));

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		retval = select(sockfd + 1, &rfds, NULL, NULL, (struct timeval *)&timeout);

		if ( retval == -1 ) {
			perror("select");
			exit(EXIT_FAILURE);
		} else if ( retval == 0 ) {
			sendRequestPacket(sockfd, pinfo);
			++ timeHasRepeat;
		} else {
			if ( FD_ISSET(sockfd, &rfds) ) {
				int recvsize = recvfrom(sockfd, pkt, pktsize, 0x0, (struct sockaddr *)(pinfo -> psv), &addrlen);

				if ( recvsize < 0x0 ) {
					sendRequestPacket(sockfd, pinfo);
					++ timeHasRepeat;
				} else {
					if ( recvsize >= pktsize ) {
						pkt[pktsize - 1] = 0x0;
					}

					phs -> recvSuccess = handleResponsePacket(pkt, pktsize);
					timeHasRepeat = 0x0;
				}
			} else {
				++ timeHasRepeat;
			}
		}

		if ( phs -> mode == 0x1 || phs -> recvSuccess == false ) {
			messageFromPacket(pkt, phs);
		}

		free(pkt);

		if ( phs -> recvSuccess ) {
			phs -> recvSuccess = false;

			if ( phs -> mode == 0x1 ) {
				struct usrinfoSet *pui = pinfo -> pui;
				int pid;
				FILE *fd;

				puts("The authentication succeeded, and now you can access Internet!");

				if ( (fd = fopen(phs -> filePath, "w")) ) {
					char info[0x100] = {0x0};
					time_t tm;

					time(&tm);
					snprintf(info, sizeof(info), INFORMATION_FILE, inet_ntoa( pinfo -> psv -> sin_addr ), phs -> service, pui -> dev, phs -> randnum, (unsigned long)tm);
					fputs(info, fd);
					fclose(fd);
				} else {
					fprintf(stderr, "fopen(%s%s, \"w\"): %s\n", "~/.", phs -> programName, strerror(errno));
				}

				if ( (pid = fork()) == 0 ) {
					phs -> mode = 0x3;
					sendRequestPacket(sockfd, pinfo);
				} else {
					if ( pid < 0 ) {
						perror("fork");
					}
					return;
				}

			} else if( phs -> mode == 0x3 ) {
				sleep(0x1e);
				sendRequestPacket(sockfd, pinfo);
			} else if( phs -> mode == 0x5 ) {
				char *tmp, s[0x14] = {0x0};
				time_t diff;

				time(&diff);
				diff -= (time_t)phs -> loginTime;

				if ( diff > (time_t)0x1517fUL ) {
					strcpy(s, "more than 24-hours");
				}

				tmp = asctime( gmtime(&diff) );
				strncpy(s, tmp + 0xb, 0x8);

				puts("Leave Internet success!");
				fprintf(stdout, "Your on-line time: %s.\n", s);
				return;
			}
		} else {
			return;
		}
	}

	if ( false ) {
	} else if ( phs -> mode == 0x1 ) {
		fputs("The authentication fails, can't receive respondence from server.\n", stderr);
	} else if ( phs -> mode == 0x3 ) {
		fputs("Keeping the link fails, can't receive respondence from server.\n", stderr);
	} else if ( phs -> mode == 0x5 ) {
		fputs("Leaving Internet fails, can't receive respondence from server. But maybe you had leave.\n", stderr);
	} else if ( phs -> mode == 0x7 ) {
		fputs("Finding the server fails, can't receive respondence from server.\n", stderr);
	}

}

static void communicationEstablishment(struct infoset * pinfo)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	getAddr(sockfd, pinfo -> pui);

	controlPacket(sockfd, pinfo);

	close(sockfd);
}

extern void aecium(int argc, char **argv)
{
	struct usrinfoSet usrinfo;
	struct sockaddr_in server_addr;
	struct hash hashinfo;
	struct infoset info;

	info.pui = &usrinfo;
	info.psv = &server_addr;
	info.phs = &hashinfo;

	memset(&usrinfo, 0x0, sizeof(struct usrinfoSet));
	memset(&hashinfo, 0x0, sizeof(struct hash));

	infoInit(argc, argv, &info);
	serverInit(&info);
	communicationEstablishment(&info);
	freeAllocateMemory(&info);
}
