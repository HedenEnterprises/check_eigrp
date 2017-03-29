#include <stdio.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <getopt.h>
#include <signal.h>

#define VERSION "0.93"
/*SNMP oids*/
#define cEigrpNbrCount "1.3.6.1.4.1.9.9.449.1.2.1.1.2.0."
#define cEigrpPeerAddr "1.3.6.1.4.1.9.9.449.1.4.1.1.3.0."
#define probeSoftwareRev "1.3.6.1.2.1.16.19.2.0"
#define ifDescr "1.3.6.1.2.1.2.2.1.2."
#define cEigrpPeerIfIndex "1.3.6.1.4.1.9.9.449.1.4.1.1.4."

/*Nagios plugin exit status:*/
enum EXITCODE { 
	OK,
	WARNING,
	CRITICAL,
	UNKNOWN
} exitcode;

/*Structure for command-line arguments*/
struct globalArgs_t {
	const char 	*HOSTNAME;	/*Hostname of monitoring router;*/
	char		*COMMUNITY;	/*SNMP Community;*/
	const char 	*NEIGHBORS;	/*Neighbors count;*/
	const char 	*AS;		/*AS number of monitoring router;*/
	int		Verbose;		/*Get or not list of neighbors (disabled by default).*/
	int		timeOut;	/*Set timeout for plugin, default is 3 seconds.*/
} globalArgs;

const char *optString = "H:C:n:a:t:vhV";
int longIndex = 0;

const struct option longOpts[] = {
	{ "hostname", required_argument, NULL, 'H' },
	{ "community", required_argument, NULL, 'C' },
	{ "neighbors", required_argument, NULL, 'n' },
	{ "asnumber", required_argument, NULL, 'a' },
	{ "timeout", required_argument, NULL, 't' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, no_argument, NULL, 0 }
};

/*Usage function, for printing help*/
void usage()
{
	printf("\ncheck_eigrp (Nagios Plugin) %s\nCopyright (C) 2014 Tiunov Igor\n", VERSION);
	printf("\nCheck status of EIGRP protocol and obtain neighbors count via SNMP\n\n\n");
	printf("Usage:\ncheck_eigrp -H <hostipaddress> -n <neighbors> -a <EIGRP AS number>\n[-C <community>] [-v]\n\n");
	printf("Options:\n -h,--help\n   Show this help message;\n");
	printf(" -V,--version\n   print the version of plugin;\n");
	printf(" -H,--hostname=ADDRESS\n   specify the hostname of router,\n   you can specify a port number by this notation:\"ADDRESS:PORT\"\n");
	printf(" -C,--community=STRING\n   specify the SNMP community of router;\n");
	printf(" -a,--asnumber=INTEGER\n   specify the EIGRP AS number of router;\n");
	printf(" -n,--neighbors=INTEGER\n   specify the neighbors count of router;\n");
	printf(" -t,--timeout=INTEGER\n   specify the timeout of plugin,\n   default is 3 sec, max 60 sec;\n");
	printf(" -v,--verbose\n   specify this key if you need to get a\n   list of neighbors (disabled by default).\n\n");
	exit(UNKNOWN);
}
/*Print the version of plugin*/
void version()
{
	printf("\ncheck_eigrp (Nagios Plugin) %s\nCopyright (C) 2014 Tiunov Igor\n", VERSION);
	printf("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	printf("Written by Tiunov Igor <igortiunov@gmail.com>\n\n");
	exit(OK);
}
/*This function open SNMP session (only structure in memory) to router*/
void* snmpopen(const char* hostname, int timeout){
	
	struct snmp_session session, *session_p;
		
	snmp_sess_init( &session );
	
	session.peername = strdup(hostname);

	session.version = SNMP_VERSION_2c;
	session.community = (u_char*) globalArgs.COMMUNITY;
	session.community_len = strlen(globalArgs.COMMUNITY);
/*
	One attempt plus session.retries, therefore
	GLOBAL timeout = session.timeout*(1+session.retries)
	Change this values if you need other timeout options:
*/
	session.retries = 2;
	session.timeout = timeout*1000000/(session.retries+1);

    snmp_enable_stderrlog();

	session_p = snmp_open(&session);

	if (session_p){
		return session_p;
	} else {
		/*Send stderr to stdout for nagios error handling*/
		dup2(1, 2);
		snmp_perror("UNKNOWN");
		snmp_log(LOG_ERR, "Some error occured in SNMP session establishment.\n");
		exit(UNKNOWN);
	}
}
/*Here we get some information from device (send and resive SNMP messages)*/
void snmpget (void *snmpsession, char *oidvalue, char *buffer, size_t buffersize){

	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);

	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	struct variable_list *vars;
/*PDU is a snmp protocol data unit.*/
	struct snmp_pdu *pdu;
	struct snmp_pdu *response;	

	/*If SNMP session is started, create pdu for OID and get the value*/
	pdu = snmp_pdu_create(SNMP_MSG_GET);

	/*OK, get the SNMP vlaue from router*/
	read_objid(oidvalue, anOID, &anOID_len);
	snmp_add_null_var(pdu, anOID, anOID_len);

	if (snmp_synch_response(snmpsession, pdu, &response) == STAT_SUCCESS) {
		if (response->errstat == SNMP_ERR_NOERROR) {
			vars = response->variables;
			if (snprint_value(buffer, buffersize, vars->name, vars->name_length, vars) == -1) {
				printf("UNKNOWN: May be this router has not EIGRP protocol? |\n");
				print_value(vars->name, vars->name_length, vars);
				snmp_free_pdu(response);
				snmp_close(snmpsession);
				exit(UNKNOWN);
			}
			snmp_free_pdu(response);
		} else {
			printf("UNKNOWN: Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
			snmp_free_pdu(response);
			snmp_close(snmpsession);
			exit(UNKNOWN);
		}
	} else {
		/*Send stderr to stdout for nagios error handling*/
		dup2(1, 2);
		snmp_sess_perror("UNKNOWN", snmpsession);
		snmp_close(snmpsession);
		exit(UNKNOWN);
	}
}
/*Print interface description*/
void printIntDesc(void* session, int count, int mutex){
	char snmpOID[100];
	char buffer[100];
	memset(snmpOID, 0, sizeof(snmpOID));
	memset(buffer, 0, sizeof(buffer));
	
	strcpy(snmpOID, cEigrpPeerIfIndex);
	snprintf(snmpOID+strlen(cEigrpPeerIfIndex), 6, "%d", mutex*65536);
	strcat(snmpOID, ".");
	strcat(snmpOID, globalArgs.AS);
	strcat(snmpOID, ".");
	snprintf(snmpOID+strlen(snmpOID), 12, "%d", count);
	snmpget(session, snmpOID, buffer, sizeof(buffer));

	memset(snmpOID, 0, sizeof(snmpOID));
	strcpy(snmpOID, ifDescr);
	strcat(snmpOID, buffer);
	snmpget(session, snmpOID, buffer, sizeof(buffer));

	printf(" %s", buffer);
}
/*
	This finction hangle alarm signal (SIGALRM)
	if some problem occurs (in UNIX socket, etc).
*/
void alarmHandler()
{
	snmp_close_sessions();
	printf("UNKNOWN: Plugin timeout exceeded for %d seconds.\n", globalArgs.timeOut);
	exit(UNKNOWN);
}

int main(int argc, char *argv[])
{
/*Default value of command-line arguments*/
	globalArgs.HOSTNAME=NULL;
	globalArgs.COMMUNITY="public";
	globalArgs.NEIGHBORS=NULL;
	globalArgs.AS=NULL;
	globalArgs.timeOut=3;
	globalArgs.Verbose=0;

/*Command-line arguments parsing*/
	int opt;
	while((opt = getopt_long(argc, argv, optString, longOpts, &longIndex)) != -1){
		switch( opt ) {
			case 'H':
				globalArgs.HOSTNAME = optarg;
				break;
			case 'C':
				globalArgs.COMMUNITY = optarg;
				break;
			case 'n':
				globalArgs.NEIGHBORS = optarg;
				break;
			case 'a':
				globalArgs.AS = optarg;
				break;
			case 't':
				if ((globalArgs.timeOut = atoi(optarg)) <= 0)
					globalArgs.timeOut = 3;
				else if (globalArgs.timeOut > 60)
					globalArgs.timeOut = 60;
				break;
			case 'v':
				globalArgs.Verbose = 1;
				break;
			case 'V':
				version();
				break;
			case 'h':
				usage();
				break;
			default:
				usage();
				break;
		}
	}

	if (globalArgs.HOSTNAME==NULL || globalArgs.NEIGHBORS==NULL || globalArgs.AS==NULL){
		usage();
	} else {
/*Set the alarm timer if some problem occurs (in UNIX socket, etc.)*/
		struct sigaction alarmAct;
		memset(&alarmAct, 0, sizeof(alarmAct));
		alarmAct.sa_handler = alarmHandler;
		sigaction(SIGALRM, &alarmAct, 0);

		alarm(globalArgs.timeOut*atoi(globalArgs.NEIGHBORS)+1);
/*Create SNMP session*/
		void* session = snmpopen(globalArgs.HOSTNAME, globalArgs.timeOut);
/*Create buffer for snmp OID*/
		char snmpOID[100];
		memset(snmpOID, 0, sizeof(snmpOID));
/*Create buffer for SNMP output value (peercount). ~4G is a maximum namber + '\0' */
		char peercount[12];
		size_t sizeOfBuffer = sizeof(peercount);
		memset(peercount, 0, sizeOfBuffer);

		strcpy(snmpOID, cEigrpNbrCount);
		strcat(snmpOID, globalArgs.AS);
/*
	Get the number of current EIGRP peers.
*/
		snmpget(session, snmpOID, peercount, sizeOfBuffer);
/*Start of Nagios Check*/
		if (strcmp(peercount, "0") == 0 ){
			exitcode=CRITICAL;
			printf("CRITICAL: This router has no EIGRP neighbors. |\n");
		} else if (strcmp(peercount, globalArgs.NEIGHBORS) != 0){
			exitcode=WARNING;
			printf("WARNING: Current neighbors counts is %s but schould be %s |\n", peercount, globalArgs.NEIGHBORS);
		} else {
			exitcode=OK;
			printf("OK: Neighbors count is %s |\n", peercount);
		}
/*End of Nagios Check*/
/*
	Get the list of current EIGRP peers.
*/		
		if ((exitcode == WARNING || exitcode == OK) && globalArgs.Verbose == 1){
/*Some integers for counts*/
			int i, peerNum;
/*Create buffer for SNMP output value (midlBuff).*/
			char midlBuff[100];
			sizeOfBuffer = sizeof(midlBuff);
			memset(midlBuff, 0, sizeOfBuffer);
/*Buffers and mutex for IOS version check*/
			char* iosver = midlBuff;
			char buffer[3];
			memset(buffer, 0, sizeof(buffer));
			int mutex=0;
/*
	Get and check the IOS version for IP address converting
*/
			snmpget(session, probeSoftwareRev, iosver, sizeOfBuffer);
/*Get the major version of IOS*/
			strncpy(buffer, iosver+1, 2);
/*If the major version of IOS is 15 then check minor version*/
			if (strcmp(buffer, "15") == 0) {
				memset(buffer, 0, sizeof(buffer));
				snprintf(buffer, 2, "%c", iosver[4]);
/*If minor version is 3 or higher then change mutex*/
				if (atoi(buffer) >= 3)
					mutex = 1;
			}
/*
	Get IP addresses
*/
			memset(snmpOID, 0, sizeof(snmpOID));
			strcpy(snmpOID, cEigrpPeerAddr);
			strcat(snmpOID, globalArgs.AS);
			strcat(snmpOID, ".");

			peerNum = atoi(peercount);
			char* peerip;
			
			for (i = 0; i<peerNum; i++) {
				memset(midlBuff, 0, sizeOfBuffer);
				peerip = midlBuff;

				/*Set peercount to correct oid position*/
				snprintf(snmpOID+strlen(cEigrpPeerAddr)+1+strlen(globalArgs.AS), 12, "%d", i);
				snmpget(session, snmpOID, peerip, sizeOfBuffer);
				/*Print the list of current EIGRP peers.*/
				printf("\t%d: ", i+1);
				if (mutex == 1)
					printf("%.*s", strlen(peerip)-2, peerip+1);
				else {
					int l;
					while ((peerip = strtok(peerip, "\" ")) != NULL){
						sscanf(peerip,"%x",&l);
						if (mutex < 3)
							printf("%d.", l);
						else
							printf("%d", l);
						peerip = NULL;
						mutex++;
					}
					mutex=0;
				}
				/*Print the interface name*/
				printIntDesc(session, i, mutex);
				printf("\n");
			}
		}
		if (session)
			snmp_close(session);
	}
	return exitcode;
}
