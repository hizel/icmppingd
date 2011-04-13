#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <iniparser.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#include <ev.h>

#include "sglib.h"

#define HASH_TAB_SIZE 20
#define STRLEN 256
#define DATALEN 64
#define STRERROR strerror(errno)


void icmp_periodic_cb (struct ev_loop *loop, ev_periodic *w_, int revents);
void icmp_cb(struct ev_loop *loop, ev_io *w_, int revents);

struct icmp_periodic{
    ev_periodic p;
    void* host;  // host* 
};

struct icmp_io{
    ev_io io;
    int s;
};

struct icmp_timeout{
    ev_timer t;
    void *r;  // Result*
};

typedef struct Result{
    uint16_t id;
    struct timeval t_out;
    struct timeval t_in;
    double delta;
    int dublicate;
    int flag_timeout;
    void *host; //host*
    struct icmp_timeout icmp_t;
    struct Result *ptr_next;
    struct Result *ptr_prev;
} Result;

typedef struct host{
    uint16_t count;
    char name[STRLEN];
    ev_tstamp interval;
    ev_tstamp offset;
    ev_tstamp delay;
    struct sockaddr_in addr;
    struct icmp_periodic icmp_p;
    int s;
    Result* list_result;
    struct host *next;
} host;



#define HOST_COMPARATOR(e1,e2) (e1->addr.sin_addr.s_addr - e2->addr.sin_addr.s_addr)
#define RESULT_COMPARATOR(e1,e2) (e1->id - e2->id)

unsigned int hash_function(host *e){
    return e->addr.sin_addr.s_addr;
}

SGLIB_DEFINE_LIST_PROTOTYPES(host, HOST_COMPARATOR, next);
SGLIB_DEFINE_LIST_FUNCTIONS(host, HOST_COMPARATOR, next);
SGLIB_DEFINE_HASHED_CONTAINER_PROTOTYPES(host, HASH_TAB_SIZE, hash_function);
SGLIB_DEFINE_HASHED_CONTAINER_FUNCTIONS(host, HASH_TAB_SIZE, hash_function);

SGLIB_DEFINE_DL_LIST_PROTOTYPES(Result, RESULT_COMPARATOR, ptr_prev, ptr_next);
SGLIB_DEFINE_DL_LIST_FUNCTIONS(Result, RESULT_COMPARATOR, ptr_prev, ptr_next);


// global hash

host *hosts[HASH_TAB_SIZE];
struct ev_loop *loop;

int main(int argc, const char *argv[]){
    dictionary* ini=NULL;
    double default_interval;
    double default_offset;
    double default_delay;
    int i,s;

    if(argc != 2){
        printf("Need one argument\n");
        return 1;
    }

    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        printf("cannot create socket: %s\n", STRERROR);
        return 1;
    }

    if(fcntl(s, F_SETFL, O_NONBLOCK) < 0){
        printf("cannot set nonblock mode socket: %s\n", STRERROR);
        return 1;
    }

    loop = ev_default_loop(0);  // ev loop!!

    ini = iniparser_load(argv[1]);
    // load default values
    default_interval = iniparser_getdouble(ini, "default:interval", 6.0);
    default_offset = iniparser_getdouble(ini, "default:offset", 1.0);
    default_delay = iniparser_getdouble(ini, "default:delay", 2.0);
    printf("defaults interval %.2f offset %.2f delay %.2f\n", default_interval, default_offset, default_delay);
    sglib_hashed_host_init(hosts);

    for(i=0;i<iniparser_getnsec(ini);i++){
        char *secname = iniparser_getsecname(ini, i);
        if(strcmp("default", secname)){
            host t;
            strncpy(t.name, secname, STRLEN);
            if(sglib_hashed_host_find_member(hosts, &t) == NULL){
                host *t;
                char key[STRLEN]; 
                ev_tstamp interval, offset, delay;
                char *ip;

                // parse ini section

                strncpy(key, secname, STRLEN);
                strncat(key, ":ip", STRLEN);
                ip = iniparser_getstring(ini, key, "127.0.0.1");

                strncpy(key, secname, STRLEN);
                strncat(key, ":interval", STRLEN);
                interval = iniparser_getdouble(ini, key, default_interval); 

                strncpy(key, secname, STRLEN);
                strncat(key, ":offset", STRLEN);
                offset = iniparser_getdouble(ini, key, default_offset); 

                strncpy(key, secname, STRLEN);
                strncat(key, ":delay", STRLEN);
                delay = iniparser_getdouble(ini, key, default_delay); 


                // create host structure

                t = (host*)malloc(sizeof(host));
                strncpy(t->name, secname, STRLEN);
                t->addr.sin_family = AF_INET;
                t->addr.sin_port = 0;
                t->addr.sin_addr.s_addr = inet_addr(ip);
                t->interval = interval;
                t->offset = offset;
                t->delay = delay;
                t->s = s; // socket
                t->icmp_p.host = t;
                t->count = 0;
                t->list_result = NULL;

                // start periodic for host

                ev_periodic_init(&t->icmp_p.p, icmp_periodic_cb, offset, interval, NULL);
                ev_periodic_start(loop, &t->icmp_p.p);

                sglib_hashed_host_add(hosts, t);

                //printf("add %s with ip:%s and interval:%.2f\n", secname, ip, interval);
            }
        }
    }

    // prepare 
    struct icmp_io icmp_watcher;
    icmp_watcher.s = s;
    ev_io_init(&icmp_watcher.io, icmp_cb, s, EV_READ);
    ev_io_start(loop, &icmp_watcher.io);

    ev_loop(loop, 0);

    printf("Yep!\n");
    return 0;
}

unsigned short checksum_ip(unsigned char *_addr, int count) {
    register long sum= 0;
    unsigned short *addr= (unsigned short *)_addr;

    while(count > 1) {
        sum += *addr++;
        count -= 2;
    }

    /* Add left-over byte, if any */
    if(count > 0)
        sum += *(unsigned char *)addr;
        
    /* Fold 32-bit sum to 16 bits */
    while(sum >> 16)
        sum= (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

void icmp_timeout_cb(struct ev_loop *loop, struct ev_timer *w_, int revents){
    struct icmp_timeout *w = (struct icmp_timeout*) w_;
    Result *r = (Result*)w->r;
    r->flag_timeout=1;
    host *h = (host*)r->host;
    printf("timeout for %s\n",  inet_ntoa(h->addr.sin_addr));
}


void icmp_periodic_cb(struct ev_loop *loop, ev_periodic *w_, int revents){
    struct icmp_periodic *w = (struct icmp_periodic*) w_;
    host* h = (host*)w->host;
    int len_out = offsetof(struct icmp, icmp_data) + DATALEN;
    uint16_t id_out;
    char buf[STRLEN];
    struct icmp *icmpout = NULL;
    struct timeval t_out;
    int n = 0;
    int s = h->s;

    id_out = getpid() & 0xFFFF;
    icmpout = (struct icmp *)buf;
    unsigned char *data = (unsigned char *)icmpout->icmp_data;
    icmpout->icmp_code  = 0;
    icmpout->icmp_type  = ICMP_ECHO;
    icmpout->icmp_id    = htons(id_out);
    icmpout->icmp_seq   = htons(h->count);
    icmpout->icmp_cksum = 0;
    gettimeofday(&t_out, NULL);
    memcpy(data, &t_out, sizeof(struct timeval));
    data += sizeof(struct timeval);
    int j;
    for (j = 0; j < DATALEN - sizeof(struct timeval); j++)
        data[j] = j;

    icmpout->icmp_cksum = checksum_ip((unsigned char *)icmpout, len_out);

    if((n = sendto(s, (char *)icmpout, len_out, 0, (struct sockaddr *)&h->addr, sizeof(struct sockaddr))) < 0){
        printf("fail send icmp %s\n", STRERROR);
    }else{
        Result *r;
        r = (Result*)malloc(sizeof(Result));
        r->id = h->count;
        r->host = h;
        r->t_out = t_out;
        r->flag_timeout = 0;
        r->icmp_t.r = r;
        ev_timer_init(&r->icmp_t.t, icmp_timeout_cb, h->delay, 0);
        ev_timer_start(loop, &r->icmp_t.t);
        sglib_Result_add(&h->list_result, r);

        //printf("Send icmp request %s\n", inet_ntoa(h->addr.sin_addr));
    }
    h->count++;
}

void icmp_cb(struct ev_loop *loop, ev_io *w_, int revents) {
    struct icmp_io *w = (struct icmp_io*) w_;
    int n;
    struct sockaddr_in sout;
    char buf[STRLEN];
    uint16_t id_in, id_out, seq_in;
    struct ip *iphdrin;
    struct icmp *icmpin = NULL;
    struct timeval t_in, t_out;
    socklen_t size = sizeof(struct sockaddr_in);

    sout.sin_family = AF_INET;
    sout.sin_port   = 0;
    
    n = recvfrom(w->s, buf, STRLEN, 0, (struct sockaddr *)&sout, &size);
    
    id_out = getpid() & 0xFFFF;
    iphdrin = (struct ip *)buf;
    icmpin  = (struct icmp *)(buf + iphdrin->ip_hl * 4);
    id_in   = ntohs(icmpin->icmp_id);
    seq_in  = ntohs(icmpin->icmp_seq);
    if (icmpin->icmp_type == ICMP_ECHOREPLY) {
        if (id_in == id_out) {
            host th,*h;
            th.addr = sout;
            if((h = sglib_hashed_host_find_member(hosts, &th)) != NULL){
                Result tr,*r;
                tr.id = seq_in;
                if((r = sglib_Result_find_member(h->list_result, &tr)) != NULL){
                    gettimeofday(&t_in, NULL);
                    memcpy(&t_out, icmpin->icmp_data, sizeof(struct timeval));
                    double delta = (double)(t_in.tv_sec - t_out.tv_sec) + (double)(t_in.tv_usec - t_out.tv_usec) / 1000000;
                    r->t_in = t_in;
                    r->delta = delta;
                    ev_timer_stop(loop, &r->icmp_t.t);
                    if(! r->flag_timeout){
                        printf("%s %f\n", inet_ntoa(sout.sin_addr), delta);
                    }else{
                        printf("%s %f timeouted\n", inet_ntoa(sout.sin_addr), delta);
                    }
                    //printf("recv from %s with delta %f\n", inet_ntoa(sout.sin_addr), delta)
                }else{
                    printf("recv from %s bad icmp :-\\ \n", inet_ntoa(sout.sin_addr));
                }
            }
        }
    }
}

