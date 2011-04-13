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

void icmp_cb(struct ev_loop *loop, ev_io *w_, int revents);
void icmp_periodic_cb(struct ev_loop *loop, ev_periodic *w_, int revents);

@class Host;

struct icmp_periodic{
    ev_periodic p;
    Host *host;
};

struct icmp_io{
    ev_io io;
    NSMutableDictionary *hosts;
    int s;
};

@interface Result: NSObject{
    struct timeval send;
    struct timeval recv;
    double delta;
    BOOL started;
    int dublicate;
}

@property (readonly) double delta;
@property (readonly) int dublicate;
@property (readonly) BOOL started;

- (void) setRecvNow;
- (void) setSendNow;

- (void) setRecv: (struct timeval) t_in;

@end

//
// Host
//

@interface Host: NSObject {
    uint16_t count;
    struct sockaddr_in addr;
    int s;
    NSMutableArray *results;
    ev_tstamp interval;
    ev_tstamp offset;
    struct icmp_periodic icmp_p;
}

@property (readonly) int s;
@property (readwrite) uint16_t count;

- (void) recv: (uint16_t) seq_in t_in: (struct timeval) t_in t_out: (struct timeval) t_out;
- (id) initWithHost: (struct sockaddr_in) newAddr interval: (ev_tstamp) newInterval offset: (ev_tstamp) newOffset socket: (int) newS withLoop: (struct ev_loop*) loop;
- (struct sockaddr_in) getAddr;

@end

//
//  Result imp
//

@implementation Result

@synthesize delta;
@synthesize started;
@synthesize dublicate;

- (id) init {
    if ( (self = [super init]) ){
        delta = -1.;
        dublicate = 0;
        started = NO;
    }
    return self;
}

- (void) setSendNow{
    gettimeofday(&send, NULL);
    started = YES;
}

- (void) setRecvNow{
    struct timeval recvtemp;
    gettimeofday(&recvtemp, NULL);    
    if(dublicate == 0 && started){
        recv = recvtemp;
        delta = (double)(recv.tv_sec - send.tv_sec) + (double)(recv.tv_usec - send.tv_usec) / 1000000;
    }
    dublicate++;
}

- (void) setRecv: (struct timeval) t_in{
    if(dublicate == 0 && started){
        recv = t_in;
        delta = (double)(recv.tv_sec - send.tv_sec) + (double)(recv.tv_usec - send.tv_usec) / 1000000;
    }
    dublicate++;
}

@end

//
// Host impl
//

@implementation Host

@synthesize s;
@synthesize count;

- (id) initWithHost: (struct sockaddr_in) newAddr interval: (ev_tstamp) newInterval offset: (ev_tstamp) newOffset socket: (int) newS withLoop: (struct ev_loop*) loop{
    if ((self = [super init])){
        count = 0;
        results = [[NSMutableArray alloc] init];
        addr = newAddr;
        interval = newInterval;
        offset = newOffset;
        icmp_p.host = self;
        s = newS;
        ev_periodic_init(&icmp_p.p, icmp_periodic_cb, offset, interval, NULL); 
        ev_periodic_start(loop, &icmp_p.p);
    }
    return self;
}

- (void) dealloc {
    [results release];
    [super dealloc];
}

- (void) recv: (uint16_t) seq_in t_in: (struct timeval) t_in t_out: (struct timeval) t_out {
    Result *r;
    NSLog(@"Eneter in recv func\n");
    @try {
        r = [results objectAtIndex: seq_in];
    }
    @catch(NSException *exception){
        NSLog(@"Yep! %d not found", seq_in);
        return;
    }    
    
}

- (struct sockaddr_in) getAddr{
    return addr;
}

@end

//
// Main 
//


int main( int argc, const char *argv[] ) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSMutableDictionary *hosts = [[NSMutableDictionary alloc] autorelease];

    struct ev_loop *loop = ev_default_loop(0);
    struct icmp_io icmp_watcher;

    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in *sa, sout;

    int i,s;

    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        NSLog(@"cannot create socket: %s\n", STRERROR);
        return 0;
    }
    if(fcntl(s, F_SETFL, O_NONBLOCK) < 0){
        NSLog(@"cannot set nonblock mode socket: %s\n", STRERROR);
        return 0;
    }

    for(i=1;i<argc;i++){
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET;
        if (getaddrinfo(argv[i], NULL, &hints, &res) != 0) {
            NSLog(@"for %s -- getaddrinfo failed: %s\n", argv[i], STRERROR);
        }
        sa = (struct sockaddr_in *)res->ai_addr;
        memcpy(&sout, sa, res->ai_addrlen);
        NSString *newKey = [[NSString alloc] initWithCString: inet_ntoa(sa->sin_addr)];
        NSLog(@"New key %@\n", newKey);
        Host *newHost = [[Host alloc] initWithHost: sout interval: 5. offset: 0. socket: s withLoop:loop];
        [hosts setObject: newHost forKey:newKey];        
    }

    if([hosts count] == 0){
        NSLog(@"No hosts\n");
        return 0;
    }else{
        NSLog(@"Starting ping %d hosts\n", [hosts count]);
    }

    icmp_watcher.hosts = hosts;
    icmp_watcher.s = s;
    ev_io_init(&icmp_watcher.io, icmp_cb, s, EV_READ);
    ev_io_start(loop, &icmp_watcher.io);
    
    ev_loop(loop, 0);

    [pool drain];
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

void icmp_periodic_cb (struct ev_loop *loop, ev_periodic *w_, int revents){
    struct icmp_periodic *w = (struct icmp_periodic*) w_;
    struct sockaddr_in sout;
    Host *host = w->host;
    int len_out = offsetof(struct icmp, icmp_data) + DATALEN;
    uint16_t id_out;
    char buf[STRLEN];
    struct icmp *icmpout = NULL;
    struct timeval t_out;
    int n = 0;
    int s = host.s;

    id_out = getpid() & 0xFFFF;
    icmpout = (struct icmp *)buf;
    unsigned char *data = (unsigned char *)icmpout->icmp_data;
    icmpout->icmp_code  = 0;
    icmpout->icmp_type  = ICMP_ECHO;
    icmpout->icmp_id    = htons(id_out);
    icmpout->icmp_seq   = htons(host.count);
    icmpout->icmp_cksum = 0;
    gettimeofday(&t_out, NULL);
    memcpy(data, &t_out, sizeof(struct timeval));
    data += sizeof(struct timeval);
    int j;
    for (j = 0; j < DATALEN - sizeof(struct timeval); j++)
        data[j] = j;
    icmpout->icmp_cksum = checksum_ip((unsigned char *)icmpout, len_out);

    sout = [host getAddr];
    sout.sin_family = AF_INET;
    sout.sin_port   = 0;
    if((n = sendto(s, (char *)icmpout, len_out, 0, (struct sockaddr *)&sout, sizeof(struct sockaddr))) < 0){
        NSLog(@"ICMP echo request for failed -- %s\n", STRERROR);
    }else{
        NSLog(@"Send icmp request %s\n", inet_ntoa(sout.sin_addr));
    }
    host.count += 1;
}



void icmp_cb(struct ev_loop *loop, ev_io *w_, int revents) {
    struct icmp_io *w = (struct icmp_io*) w_;
    NSMutableDictionary *hosts = w->hosts;
    int n;
    struct sockaddr_in sout;
    char buf[STRLEN];
    uint16_t id_in, id_out, seq_in;
    struct ip *iphdrin;
    struct icmp *icmpin = NULL;
    struct timeval t_in, t_out;
    socklen_t size = sizeof(struct sockaddr_in);

    NSLog(@"Enter to icmp cb");

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
            NSString* stringIP = [[NSString alloc] initWithCString: inet_ntoa(sout.sin_addr) ];
            Host *h = [hosts objectForKey: stringIP];
            if(h){
                NSLog(@"Found entire for %@", stringIP);
                gettimeofday(&t_in, NULL);
                memcpy(&t_out, icmpin->icmp_data, sizeof(struct timeval));
                [h recv:seq_in t_in:t_in t_out:t_out];
            }else{
                NSLog(@"Not Found entire for %@", stringIP);
            }
        }
    }
}
