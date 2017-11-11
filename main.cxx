#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>    /* Must precede if*.h */
#include <assert.h>

// EAPOL encapsulation: http://www.vocal.com/secure-communication/eapol-extensible-authentication-protocol-over-lan/
// EAP: http://tools.ietf.org/html/rfc3748


#define ETH_ALEN        6       /* Octets in one ethernet addr   */
#define ETH_HLEN        14      /* Total octets in header.   */
#define ETH_ZLEN        60      /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500        /* Max. octets in payload    */
#define ETH_FRAME_LEN   1514        /* Max. octets in frame sans FCS */

#define ETH_P_EAP       0x888e
#define ETH_P_802       0x8100

enum {
    EAP_CODE_REQUEST  = 1,
    EAP_CODE_RESPONSE,
    EAP_CODE_SUCCESS,
    EAP_CODE_FAILURE
};

const char * internal_devname = "enp3s0";
const char * external_devname = "enp4s0";

struct context {
    u_char success;
};

struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char   h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short  h_proto;        /* packet type ID field */
} __attribute__((packed));

struct ethframe
{
    ethhdr  hdr;
    u_char  payload[ETH_DATA_LEN];
};

struct CaptureThread
{
    const char * devname;
    pthread_t thread;
    pcap_t * handle;

    CaptureThread(const char * name)
    {
        this->devname = name;
        this->handle = NULL;
        this->thread = 0;
    }

    void start()
    {
        pthread_create(&thread, NULL, CaptureThread::_thread_entry, (void *)this);
    }

    void join()
    {
        void *arg;

        pthread_join(thread, &arg);
    }

    static void * _thread_entry(void *arg)
    {
        CaptureThread * me = (CaptureThread *)arg;

        return me->thread_entry();
    }

    void * thread_entry();
};

FILE * logfile = stderr;

struct context shared_context;
CaptureThread internal(internal_devname);
CaptureThread external(external_devname);

#define TIME_LEN 100

char * make_time() {
    char *time_string = (char *)malloc(TIME_LEN);
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    tmp = localtime(&t);
    strftime(time_string, TIME_LEN, "[%D %_H:%0M:%0S]", tmp);

    return time_string;
}

void print_ethernet_header(char *time_str, const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "%s Ethernet Header\n", time_str);
    fprintf(logfile , "%s    |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            time_str,
            eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] ,
            eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "%s    |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
            time_str,
            eth->h_source[0] , eth->h_source[1] , eth->h_source[2] ,
            eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "%s    |-Protocol            : 0x%04x \n",
            time_str,
            (unsigned short)ntohs(eth->h_proto));

    int lc = 0;

    char buf[16];

    for(int i = 0; i < Size; i++)
    {
        if(lc == 0)
            fprintf(logfile, "%s    0x%08x: ", time_str, i);

        fprintf(logfile, "%02x", Buffer[i]);
        buf[lc] = Buffer[i];
        lc += 1;

        if(lc == 16)
        {
            fprintf(logfile, "    ");
            for(int j=0; j<lc; j++)
                fprintf(logfile, "%c", buf[j] > 32 ? buf[j] : '.');

            fprintf(logfile, "\n");
            lc = 0;
        }
        else
        {
            fprintf(logfile, " ");
        }
    }

    for(int j=0; j<lc; j++)
        fprintf(logfile, "%c", buf[j] > 32 ? buf[j] : '.');
    fprintf(logfile, "\n");
}

const char * eapcodestr(int code)
{
    switch(code)
    {
        case EAP_CODE_REQUEST: return "REQUEST";
        case EAP_CODE_RESPONSE: return "RESPONSE";
        case EAP_CODE_SUCCESS: return "SUCCESS";
        case EAP_CODE_FAILURE: return "FAILURE";
    }

    return "UNKNOWN";
}

const char * eaptypestr(int type)
{
    switch(type)
    {
        case 1: return "IDENTITY";
        case 2: return "NOTIFICATION";
        case 3: return "NAK";
        case 4: return "MD5-CHALLENGE";
    }

    return "";
}

void print_eapol(char *time_str, const u_char *Buffer, int Size)
{
    Buffer += sizeof(ethhdr);

    u_char  encver  = Buffer[0];
    u_char  enctype = Buffer[1];
    u_short enclen  = (Buffer[2] << 8) | Buffer[3];

    u_char  code  = Buffer[4];
    u_char  id    = Buffer[5];
    u_short len   = (Buffer[6] << 8) | Buffer[7];
    u_char  type  = Buffer[8];

    fprintf(logfile, "%s   EncVer:%d\n", time_str, encver);
    fprintf(logfile, "%s  EncType:%d\n", time_str, enctype);
    fprintf(logfile, "%s   EncLen:%d\n", time_str, enclen);
    fprintf(logfile, "%s     Code:%d (%s)\n", time_str, code, eapcodestr(code));
    fprintf(logfile, "%s       Id:%d\n", time_str, id);
    fprintf(logfile, "%s      Len:%d\n", time_str, len);
    fprintf(logfile, "%s     Type:%d (%s)\n", time_str, type, eaptypestr(type));
}

void print_packet(char *time_str, const u_char *Buffer, int Size)
{
    print_ethernet_header(time_str, Buffer, Size);
    print_eapol(time_str, Buffer, Size);
}


void internal_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *time_str = make_time();
    struct ethhdr *eth = (struct ethhdr *)packet;

    fprintf(logfile, "%s ------------------------------------------------------------------------------------------------------------\n", time_str);
    fprintf(logfile, "%s Received %d bytes from internal interface\n", time_str, header->len);

    u_char code = packet[sizeof(ethhdr) + 4];
    if(code != EAP_CODE_RESPONSE || !shared_context.success) {
        int r = pcap_inject(external.handle, packet, header->len);

        print_packet(time_str, packet, header->len);

        fprintf(logfile, "%s Forwarded %d bytes to external interface\n", time_str, r);
        fprintf(logfile, "%s\n", time_str);
    }

    free(time_str);
}


void external_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *time_str = make_time();
    struct ethhdr *eth = (struct ethhdr *)packet;

    fprintf(logfile, "%s ------------------------------------------------------------------------------------------------------------\n", time_str);
    fprintf(logfile, "%s Received %d bytes from external interface\n", time_str, header->len);

    print_packet(time_str, packet, header->len);

    u_char code = packet[sizeof(ethhdr) + 4];
    if(code == EAP_CODE_SUCCESS) {
        shared_context.success = 1;
    }
    else {
        shared_context.success = 0;
    }

    int r = pcap_inject(internal.handle, packet, header->len);

    fprintf(logfile, "%s Forwarded %d bytes to internal interface\n", time_str, r);
    fprintf(logfile, "%s \n", time_str);

    free(time_str);
}


void * CaptureThread::thread_entry()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * eap_filter = "ether proto 0x888e or ether proto 0x8100";
    struct bpf_program eap_program;

    handle = pcap_open_live(devname, BUFSIZ, true, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
        exit(2);
    }

    if (pcap_compile(handle, &eap_program, eap_filter, 1, 0) == -1)
    {
        pcap_geterr(handle);
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", eap_filter, errbuf);
        exit(2);
    }

    if (pcap_setfilter(handle, &eap_program) == -1)
    {
        pcap_geterr(handle);
        fprintf(stderr, "Couldn't install filter '%s': %s\n", eap_filter, errbuf);
        exit(2);
    }

    if(!strcmp(devname, internal_devname))
        pcap_loop(handle, -1, internal_callback, NULL);
    else
        pcap_loop(handle, -1, external_callback, NULL);

    /* And close the session */
    pcap_close(handle);

    return NULL;
}

int main(int argc, const char **argv)
{
    char *time_str = make_time();
    memset(&shared_context, 0, sizeof(struct context));
    shared_context.success = 1;

    fprintf(logfile, "%s eapolproxy starting %s\n", time_str, __DATE__);

    fprintf(logfile, "%s starting %s\n", time_str, internal_devname);
    internal.start();
    while(internal.handle == NULL)
        usleep(100000);

    fprintf(logfile, "%s starting %s\n", time_str, external_devname);
    external.start();

    while(external.handle == NULL)
        usleep(100000);

    fprintf(logfile, "%s ready\n", time_str);

    free(time_str);

    internal.join();
    external.join();

    return 1;
}

