#include <stdio.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <getopt.h>
#include <signal.h>


#define VERSION "0.1.0"


/* SNMP oids */
#define OID_EIGRP_NEIGHBOR_COUNT       "1.3.6.1.4.1.9.9.449.1.2.1.1.2.0."
#define OID_EIGRP_PEER_ADDRESS         "1.3.6.1.4.1.9.9.449.1.4.1.1.3.0."
#define OID_PROBE_SOFTWARE_REVISION    "1.3.6.1.2.1.16.19.2.0"
#define OID_INTERFACE_DESCRIPTION      "1.3.6.1.2.1.2.2.1.2."
#define OID_EIGRP_PEER_INTERFACE_INDEX "1.3.6.1.4.1.9.9.449.1.4.1.1.4."


/* snmp macros */
#define _GET(oid) snmpget(session, oid, buffer, sizeof(buffer))


/* Nagios plugin exit status */
enum EXITCODE { 
    OK,
    WARNING,
    CRITICAL,
    UNKNOWN
} exitcode;


/* Structure for command-line arguments */
struct globalArgs_t {
    const char  * HOSTNAME;       /* Hostname of monitoring router */
    char        * COMMUNITY;      /* SNMP Community */
    const char  * NEIGHBORS;      /* Neighbors count */
    const char  * AS;             /* AS number of monitoring router */
    int           Verbose;        /* Get or not list of neighbors (disabled by default) */
    int           timeOut;        /* Set timeout for plugin, default is 3 seconds */
    int           snmpVersion;    /* which version of snmp 1,2,3 */
    const char  * v3Context;      /* v3 snmp context */
    int           v3secLevel;     /* v3 security level, one of SECLEVEL_* definitions */
    int           v3authProto;    /* v3 authentication protocol, one of AUTHPROTO_* definitions */
    int           v3privProto;    /* v3 privacy protocol, one of PRIVPROTO_* definitions */
    const char  * v3secName;      /* v3 username */
    const char  * v3authPassword; /* v3 authentication password */
    const char  * v3privPassword; /* v3 privacy password */
} globalArgs;


const char * optString = "H:C:n:s:t:vhVp:c:L:a:x:U:A:X:";
int longIndex = 0;


const struct option longOpts[] = {
    { "hostname",   required_argument, NULL, 'H' },
    { "community",  required_argument, NULL, 'C' },
    { "neighbors",  required_argument, NULL, 'n' },
    { "asnumber",   required_argument, NULL, 's' },
    { "timeout",    required_argument, NULL, 't' },
    { "verbose",    no_argument,       NULL, 'v' },
    { "help",       no_argument,       NULL, 'h' },
    { "version",    no_argument,       NULL, 'V' },
    { "protocol",   required_argument, NULL, 'p' },
    { "context",    required_argument, NULL, 'c' },
    { "seclevel",   required_argument, NULL, 'L' },
    { "authproto",  required_argument, NULL, 'a' },
    { "privproto",  required_argument, NULL, 'x' },
    { "secname",    required_argument, NULL, 'U' },
    { "authpasswd", required_argument, NULL, 'A' },
    { "privpasswd", required_argument, NULL, 'X' },
    { NULL,         no_argument,       NULL,  0  }
};


/*Usage function, for printing help*/
void usage(char * error)
{
    if (error != NULL) {
        printf("%s\n", error);
    }
    version();
    printf("%s\n", "");
    printf("%s\n", "Check status of EIGRP protocol and obtain neighbors count via SNMP");
    printf("%s\n", "");
    printf("%s\n", "");
    printf("%s\n", "");
    printf("%s\n", "Usage:");
    printf("%s\n", "check_eigrp [OPTIONS]");
    printf("%s\n", "");
    printf("%s\n", "");
    printf("%s\n", "Options:");
    printf("%s\n", " -h, --help");
    printf("%s\n", "   Show this help message");
    printf("%s\n", "");
    printf("%s\n", " -V, --version");
    printf("%s\n", "   print the version of plugin");
    printf("%s\n", "");
    printf("%s\n", " -H, --hostname=ADDRESS");
    printf("%s\n", "   specify the hostname of router,");
    printf("%s\n", "   you can specify a port number by this notation:\"ADDRESS:PORT\"");
    printf("%s\n", "");
    printf("%s\n", " -p, --protocol=STRING");
    printf("%s\n", "   specify snmp version to use one of (1|2c|3)");
    printf("%s\n", "   defaults to 2c");
    printf("%s\n", "");
    printf("%s\n", " -c, --context");
    printf("%s\n", "   SNMPv3 context");
    printf("%s\n", "");
    printf("%s\n", " -L, --seclevel=STRING");
    printf("%s\n", "   SNMPv3 security level: one of (noAuthNoPriv|authNoPriv|authPriv)");
    printf("%s\n", "   defaults to noAuthNoPriv");
    printf("%s\n", "");
    printf("%s\n", " -a, --authproto=STRING");
    printf("%s\n", "   SNMPv3 authentication protocol: one of (md5|sha)");
    printf("%s\n", "   defaults to md5");
    printf("%s\n", "");
    printf("%s\n", " -x, --privproto=STRING");
    printf("%s\n", "   SNMPv3 privacy protocol: one of (des|aes)");
    printf("%s\n", "   defaults to des");
    printf("%s\n", "");
    printf("%s\n", " -U, --secname=STRING");
    printf("%s\n", "   SNMPv3 username");
    printf("%s\n", "");
    printf("%s\n", " -A, --authpasswd=STRING");
    printf("%s\n", "   SNMPv3 authentication password");
    printf("%s\n", "");
    printf("%s\n", " -X, --privpasswd=STRING");
    printf("%s\n", "   SNMPv3 privacy password");
    printf("%s\n", "");
    printf("%s\n", " -C, --community=STRING");
    printf("%s\n", "   specify the SNMP community of router");
    printf("%s\n", "");
    printf("%s\n", " -s, --asnumber=INTEGER");
    printf("%s\n", "   specify the EIGRP AS number of router");
    printf("%s\n", "");
    printf("%s\n", " -n, --neighbors=INTEGER");
    printf("%s\n", "   specify the neighbors count of router");
    printf("%s\n", "");
    printf("%s\n", " -t, --timeout=INTEGER");
    printf("%s\n", "   specify the timeout of plugin,");
    printf("%s\n", "   default is 3 sec, max 60 sec");
    printf("%s\n", "");
    printf("%s\n", " -v, --verbose");
    printf("%s\n", "   specify this key if you need to get a");
    printf("%s\n", "   list of neighbors (disabled by default).");
    printf("%s\n", "");
    printf("%s\n", "");
}


/*Print the version of plugin*/
void version()
{
    printf("%s\n", "check_eigrp (Nagios Plugin) %s", VERSION);
    printf("%s\n", "Copyright (C) 2014 Tiunov Igor");
    printf("%s\n", "");    
    printf("%s\n", "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.");
    printf("%s\n", "This is free software: you are free to change and redistribute it.");
    printf("%s\n", "There is NO WARRANTY, to the extent permitted by law.");
    printf("%s\n", "Written by Tiunov Igor <igortiunov@gmail.com>");
    printf("%s\n", "SNMPv3 added by Bryan Heden <b.heden@gmail.com>");
}


void stderr_to_stdout()
{
    dup2(1, 2);
}


void * snmpopen(struct snmp_session session)
{
    struct snmp_session session * session_p;

    session_p = snmp_open(&session);


    return session_p;
}


/* Here we get some information from device (send and resive SNMP messages) */
void snmpget(void * session_ptr, char * oid_value, char * buffer, size_t buffer_size)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);

    oid                    some_oid[MAX_OID_LEN] = { 0 };
    size_t                 some_oid_len          = MAX_OID_LEN;
    struct snmp_pdu      * pdu                   = NULL;
    struct snmp_pdu      * response              = NULL;
    int                    response_return       = 0;
    int                    errors                = 0;

    pdu = snmp_pdu_create(SNMP_MSG_GET);

    read_objid(oid_value, some_oid, &some_oid_len);
    snmp_add_null_var(pdu, some_oid, some_oid_len);

    response_return = snmp_synch_response(session_ptr, pdu, &response);
    if (response_return == STAT_SUCCESS) {
        if (response->errstat == SNMP_ERR_NOERROR) {

            struct variable_list * vars = response->variables;

            if (vars == NULL) {
                errors++;
            }
            else if (snprint_value(buffer, buffer_size, vars->name, vars->name_length, vars) == -1) {
                printf("%s\n", "UNKNOWN: May be this router has not EIGRP protocol? |");
                print_value(vars->name, vars->name_length, vars);
                errors++;
            }
        }
        else {
            printf("UNKNOWN: Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
            errors++;
        }

        if (errors > 0) {
            snmp_free_pdu(response);
        }
    }
    else {
        stderr_to_stdout();
        snmp_sess_perror("UNKNOWN", session_ptr);
        errors++;
    }

    if (errors > 0) {
        snmp_close(session_ptr);
        exit(UNKNOWN);
    }
}


/*Print interface description*/
void print_interface_description(void* session, char * asnumber, int count, int mutex)
{
    char snmp_oid[100] = { 0 };
    char buffer[100] = { 0 };
    
    strcpy(snmp_oid, OID_EIGRP_PEER_INTERFACE_INDEX);
    snprintf(snmp_oid, sizeof(snmp_oid), "%s%d.%s.%d", OID_EIGRP_PEER_INTERFACE_INDEX,
                                                       (mutex * 65536),
                                                       asnumber,
                                                       count);

    snmpget(session, snmp_oid, buffer, sizeof(buffer));

    memset(snmp_oid, 0, sizeof(snmp_oid));
    strcpy(snmp_oid, OID_INTERFACE_DESCRIPTION);
    strcat(snmp_oid, buffer);
    snmpget(session, snmp_oid, buffer, sizeof(buffer));

    printf(" %s", buffer);
}


void alarm_handler()
{
    snmp_close_sessions();
    printf("%s\n", "UNKNOWN: Plugin timeout exceeded");
    exit(UNKNOWN);
}


int main(int argc, char *argv[])
{
    struct snmp_session   session     = { 0 };
    struct snmp_session * session_ptr = NULL;

    int    verbosity = 0;
    int    timeout   = 3;
    char * asnumber  = NULL;
    char * neighbors = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, optString, longOpts, &longIndex)) != -1) {
        switch (opt) {

        case 'H':
            session.peername = optarg;
            break;

        case 'C':
            session.community = (unsigned char *) optarg;
            session.community_len = strlen(optarg);
            break;

        case 'n':
            neighbors = optarg;
            break;

        case 's':
            asnumber = optarg;
            break;

        case 't':
            timeout = atoi(optarg);
            if (timeout < 3) {
                timeout = 3;
            }
            else if (timeout > 60) {
                timeout = 60;
            }
            break;

        case 'p':
            int protocol = atoi(optarg);
            if (protocol == 3) {
                session.version = SNMP_VERSION_3;
            }
            else if (protocol == 2) {
                session.version = SNMP_VERSION_2c;
            }
            else if (protocol == 1) {
                session.version = SNMP_VERSION_1;
            }
            break;

        case 'c':
            session.contextName = optarg;
            session.contextNameLen = strlen(optarg);
            break;

        case 'L':
            if (!strcasecmp("noAuthNoPriv", optarg)) {
                session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
            }
            else if (!strcasecmp("AuthNoPriv", optarg)) {
                session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
            }
            else if (!strcasecmp("AuthPriv", optarg)) {
                session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            }
            else {
                /* error */
            }
            break;

        case 'a':
            if (!strcasecmp("sha", optarg)) {
                session.securityAuthProto = usmHMACSHA1AuthProtocol;
                session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
            }
            else if (!strcasecmp("md5", optarg)) {
                session.securityAuthProto = usmHMACMD5AuthProtocol;
                session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
            }
            else {
                /* error */
            }
            break;

        case 'x':
            if (!strcasecmp("aes", optarg)) {
                session.securityPrivProto = usmAESPrivProtocol;
                session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
            }
            else if (!strcasecmp("des", optarg)) {
                session.securityPrivProto = usmDESPrivProtocol;
                session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
            }
            else {
                /* error */
            }
            break;

        case 'U':
            session.securityName = optarg;
            session.securityNameLen = strlen(optarg);
            break;

        case 'A':
            session.securityAuthKey = (unsigned char *) optarg;
            session.securityAuthKeyLen = strlen(optarg);
            break;

        case 'X':
            session.securityPrivKey = (unsigned char *) optarg;
            session.securityPrivKeyLen = strlen(optarg);
            break;

        case 'v':
            verbosity++;
            break;

        case 'V':
            version();
            exit(UNKNOWN);
            break;

        case 'h':
        default:
            usage(NULL);
            exit(UNKNOWN);
            break;
        }
    }

    /* handle errors */
    {
        int errors = 0;

        if (session.peername == NULL) {
            usage("Hostname (-H flag) must be set!");
            errors++;
        }

        if (neighbors == NULL) {
            usage("Neighbors (-n flag) must be set!");
            errors++;
        }

        if (asnumber == NULL) {
            usage("ASNumber (-s flag) must be set!");
            errors++;
        }

        if (errors > 0) {
            exit(UNKNOWN);
        }
    }

    {
        /* signal handler and timeout */
        struct sigaction sa_alarm = { 0 };
        alarmAct.sa_handler = alarm_handler;
        sigaction(SIGALRM, &sa_alarm, 0);
        alarm(timeout * atoi(neighbors) + 1);

        session.retries = 2;
        session.timeout = timeout * 1000000 / (session.retries + 1);
    }

    if (verbosity > 0) {
        snmp_enable_stderrlog();
    }

    session_p = snmp_open(&session);

    if (session_p == NULL) {
        stderr_to_stdout();
        snmp_perror("UNKNOWN");
        snmp_log(LOG_ERR, "Some error occured in SNMP session establishment.\n");
        exit(UNKNOWN);
    }

    char snmp_oid[100] = { 0 };

    char peer_count[12] = { 0 };
    size_t buffer_size = sizeof(peer_count);

    strcpy(snmp_oid, OID_EIGRP_NEIGHBOR_COUNT);
    strcat(snmp_oid, asnumber);

    snmpget(session, snmp_oid, peer_count, buffer_size);

    if (strcmp(peer_count, "0") == 0) {
        exitcode = CRITICAL;
        printf("CRITICAL: This router has no EIGRP neighbors. |\n");
    }
    else if (strcmp(peer_count, neighbors) != 0) {
        exitcode = WARNING;
        printf("WARNING: Current neighbors counts is %s but schould be %s |\n", peer_count, neighbors);
    }
    else {
        exitcode = OK;
        printf("OK: Neighbors count is %s |\n", peer_count);
    }

    /* Get the list of current EIGRP peers. */
    if ((exitcode == WARNING || exitcode == OK) && verbosity > 0) {

        /* Some integers for counts */
        int i, peerNum;

        /* Create buffer for SNMP output value (midlBuff). */
        char midlBuff[100] = { 0 };
        buffer_size = sizeof(midlBuff);

        /* Buffers and mutex for IOS version check */
        char * iosver = midlBuff;
        char buffer[3] = { 0 };
        int mutex = 0;

        /* Get and check the IOS version for IP address converting */
        snmpget(session, OID_PROBE_SOFTWARE_REVISION, iosver, buffer_size);

        /* Get the major version of IOS */
        strncpy(buffer, iosver + 1, 2);

        /* If the major version of IOS is 15 then check minor version */
        if (strcmp(buffer, "15") == 0) {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, 2, "%c", iosver[4]);

            /* If minor version is 3 or higher then change mutex */
            if (atoi(buffer) >= 3) {
                mutex = 1;
            }
        }

        /* Get IP addresses */
        memset(snmp_oid, 0, sizeof(snmp_oid));
        strcpy(snmp_oid, OID_EIGRP_PEER_ADDRESS);
        strcat(snmp_oid, globalArgs.AS);
        strcat(snmp_oid, ".");

        peerNum = atoi(peer_count);
        char* peerip;
        
        for (i = 0; i < peerNum; i++) {
            memset(midlBuff, 0, buffer_size);
            peerip = midlBuff;

            /* Set peer_count to correct oid position */
            snprintf(snmp_oid + strlen(OID_EIGRP_PEER_ADDRESS) + 1 + strlen(globalArgs.AS), 12, "%d", i);
            snmpget(session, snmp_oid, peerip, buffer_size);
            
            /* Print the list of current EIGRP peers. */
            printf("\t%d: ", i + 1);
            if (mutex == 1) {
                printf("%.*s", strlen(peerip) - 2, peerip + 1);
            }
            else {
                int l;
                while ((peerip = strtok(peerip, "\" ")) != NULL) {
                    sscanf(peerip, "%x", &l);
                    if (mutex < 3) {
                        printf("%d.", l);
                    }
                    else {
                        printf("%d", l);
                    }
                    peerip = NULL;
                    mutex++;
                }
                mutex = 0;
            }

            /* Print the interface name */
            print_interface_description(session, asnumber, i, mutex);
            printf("%s\n", "");
        }
    }
    if (session) {
        snmp_close(session);
    }
        
    return exitcode;
}
