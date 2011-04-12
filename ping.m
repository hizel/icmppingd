#import <Foundation/Foundation.h>

#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <ev.h>

#import <assert.h>

#import <sys/types.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <netdb.h>
#import <fcntl.h>

#import <arpa/inet.h>
#import <netinet/ip_icmp.h>
#import <sys/time.h>

#define DATALEN 64
#define STRLEN 256
#define STRERROR strerror(errno)

@interface Result: NSObject {
    struct timeval send;
    struct timeval recv;
    double delta;
}

- (double) delta;
- (void) setSend: (struct timeval) sendVal;
- (void) setRecv: (struct timeval) recvVal;
- (void) setRecvNow;
- (void) setSendNow;
    
@end

@implementation Result

- (id)init {
    if ( (self = [super init]) ){
        delta = -1.;
    }
    return self;
}

- (double) delta{
    return delta;
}


- (void) setSend: (struct timeval) sendVal{
    send = sendVal;
}

- (void) setRecv: (struct timeval) recvVal{
    recv = recvVal;
    delta = (double)(recv.tv_sec - send.tv_sec) + (double)(recv.tv_usec - send.tv_usec) / 1000000;
}

- (void) setRecvNow{
    gettimeofday(&recv, NULL);
    delta = (double)(recv.tv_sec - send.tv_sec) + (double)(recv.tv_usec - send.tv_usec) / 1000000;
}

- (void) setSendNow{
    gettimeofday(&send, NULL);
}

@end


@interface Host: NSObject {
    uint16_t count;
    struct addrinfo host;
    NSMutableArray *resultItems;
    ev_tstamp interval;
    ev_tstamp offset;
}

- (ev_tstamp) interval;
- (ev_tstamp) offset;
- (uint16_t) count;
- (struct addrinfo) host;

- (void) setInterval: (ev_tstamp) input;
- (void) setOffset: (ev_tstamp) input;
- (void) incCount;
- (void) setHost: (struct addrinfo) input;

- (NSUInteger) resultCount;

@end

@implementation Host

- (id)init {
    if ( (self = [super init]) ) 
        resultItems = [[NSMutableArray alloc] initWithCapacity: 100];
    return self;
}

- (void)dealloc {
    [resultItems release];
    [super dealloc];
}


- (ev_tstamp) interval{
    return interval;
}

- (ev_tstamp) offset{
    return offset;
}

- (uint16_t) count{
    return count;
}

- (struct addrinfo) host{
    return host;
}

- (void) setInterval: (ev_tstamp) input{
    interval = input;
}

- (void) setOffset: (ev_tstamp) input{
    offset = input;
}

- (void) incCount{
    count++;
}

- (void) setHost: (struct addrinfo) input{
    host = input;
}

- (NSUInteger) resultCount{
    return [ resultItems count ];
}

@end

@interface Worker: NSObject {
    NSMutableSet *hosts;

- (void) addHost: (const char*) hostname;
}

@end


int count=0;
struct addrinfo *host;
int s;

unsigned short checksum_ip(unsigned char *_addr, int count);
void icmp_cb(EV_P_ ev_io *w, int revents);
void clock_cb (struct ev_loop *loop, ev_periodic *w, int revents);

int main( int argc, const char *argv[] ) {
    const char* hostname = argv[1];
    struct addrinfo hints;

    NSMutableSet *hostsSet = [NSMutableSet setWithCapacity:10];


    Host *host1 = [[Host alloc] init];

    NSLog(@"count = %d \n", [host1 resultCount]);

    [host1 release];

    struct ev_loop *loop = ev_default_loop(0);
    ev_io icmp_watcher;
    ev_periodic icmp_tick;

    assert(hostname);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    if (getaddrinfo(hostname, NULL, &hints, &host) != 0) {
        NSLog(@"ICMP echo for %s -- getaddrinfo failed: %s\n", hostname, STRERROR);
        return 0;
    }

    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        NSLog(@"ICMP echo for %s -- cannot create socket: %s\n", hostname, STRERROR);
        return 0;
    }
    fcntl(s, F_SETFL, O_NONBLOCK);

    // init ev
    ev_io_init(&icmp_watcher, icmp_cb, s, EV_READ);
    ev_io_start(loop, &icmp_watcher);

    ev_periodic_init(&icmp_tick, clock_cb, 0., 10., 0);
    ev_periodic_start(loop, &icmp_tick);

    ev_loop(loop, 0);

    NSLog(@"hello world\n");
    close(s);
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

void icmp_cb(EV_P_ ev_io *w, int revents) {
    int n;
    struct sockaddr_in *sa;
    struct sockaddr_in sout;
    char buf[STRLEN];
    uint16_t id_in, id_out, seq_in;
    struct ip *iphdrin;
    struct icmp *icmpin = NULL;
    struct timeval t_in, t_out;
    double response = -1.;
    socklen_t size = sizeof(struct sockaddr_in);

    sa = (struct sockaddr_in *)host->ai_addr;
    memcpy(&sout, sa, host->ai_addrlen);
    sout.sin_family = AF_INET;
    sout.sin_port   = 0;

    n = recvfrom(s, buf, STRLEN, 0, (struct sockaddr *)&sout, &size);

    id_out = getpid() & 0xFFFF;
    iphdrin = (struct ip *)buf;
    icmpin  = (struct icmp *)(buf + iphdrin->ip_hl * 4);
    id_in   = ntohs(icmpin->icmp_id);
    seq_in  = ntohs(icmpin->icmp_seq);
    if (icmpin->icmp_type == ICMP_ECHOREPLY) {
        if (id_in == id_out && seq_in <= (uint16_t)count) {
            gettimeofday(&t_in, NULL);
            memcpy(&t_out, icmpin->icmp_data, sizeof(struct timeval));
            response = (double)(t_in.tv_sec - t_out.tv_sec) + (double)(t_in.tv_usec - t_out.tv_usec) / 1000000;
            NSLog(@"ICMP echo response for %s succeeded %d -- received id=%d sequence=%d response_time=%fs\n", inet_ntoa(sout.sin_addr), count, id_in, seq_in, response);

        } else {
            NSLog(@"ICMP echo response for %s error %d -- received id=%d sequence=%d response_time=%fs\n", inet_ntoa(sout.sin_addr), count, id_in, seq_in, response);
        }
    }
}

void clock_cb (struct ev_loop *loop, ev_periodic *w, int revents){
    struct sockaddr_in *sa;
    struct sockaddr_in sout;
    int len_out = offsetof(struct icmp, icmp_data) + DATALEN;
    uint16_t id_out;
    char buf[STRLEN];
    struct icmp *icmpout = NULL;
    struct timeval t_out;
    int n = 0;

    id_out = getpid() & 0xFFFF;
    icmpout = (struct icmp *)buf;
    unsigned char *data = (unsigned char *)icmpout->icmp_data;
    icmpout->icmp_code  = 0;
    icmpout->icmp_type  = ICMP_ECHO;
    icmpout->icmp_id    = htons(id_out);
    icmpout->icmp_seq   = htons(count);
    icmpout->icmp_cksum = 0;
    gettimeofday(&t_out, NULL);
    memcpy(data, &t_out, sizeof(struct timeval));
    data += sizeof(struct timeval);
    int j;
    for (j = 0; j < DATALEN - sizeof(struct timeval); j++)
        data[j] = j;
    icmpout->icmp_cksum = checksum_ip((unsigned char *)icmpout, len_out);

    sa = (struct sockaddr_in *)host->ai_addr;
    memcpy(&sout, sa, host->ai_addrlen);
    sout.sin_family = AF_INET;
    sout.sin_port   = 0;
    if((n = sendto(s, (char *)icmpout, len_out, 0, (struct sockaddr *)&sout, sizeof(struct sockaddr))) < 0){
        NSLog(@"ICMP echo request for failed -- %s\n", STRERROR);
    }
    count += 1;
}
