
#ifndef FT_PING_H
# define FT_PING_H

#include "libft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <math.h>
#include <linux/errqueue.h>


#define C_MAXPACKET 10240

#define ADDR_MAX_LEN 256

#define ICMP_MAXDATA IP_MAXPACKET - 8

#define IP_HDR_SIZE 20
#define PACKET_SIZE ICMP_MINLEN + g_ping_env.spec.packetlen


#define DEFAULT_PACKETLEN 56
#define DEFAULT_TTL 64
#define DEFAULT_TIMEOUT_SEC 1
#define DEFAULT_INTERVAL 1

#define LOSS_PERCENT(X, Y) (100.0 - ((float)(X) / (float)(Y) * 100.0))

#define OPT_HELP        ((0x1) << 0)
#define OPT_VERBOSE     ((0x1) << 1)
#define OPT_NUMERIC     ((0x1) << 3)
#define OPT_INTERVAL    ((0x1) << 2)
#define OPT_SIZE        ((0x1) << 4)
#define OPT_TTL         ((0x1) << 5)
#define OPT_TIMEOUT     ((0x1) << 6)
#define OPT_NPACKET     ((0x1) << 7)

#define PROGNAME            "ft_ping"

#define ERR_NULL_ARG_MSG    "option requires an argument -- %c"
#define ERR_RANGE_ARG_MSG   "invalid argument: '%s': out of range: %ld <= value <= %ld"
#define ERR_HOST_UNFOUND    "%s: No address associated with hostname"
#define ERR_INVALID_ARG     "invalid argument: '%s'"

#define ERR_N_PACKET_SIZE   "illegal negative packet size %d.\n"
#define ERR_L_PACKET_SIZE   "packet size too large: %d\n"

#define EWMA_ALPHA  0.5
#define RTT_EWMA(RTT)    ((EWMA_ALPHA * RTT) + ((1 - EWMA_ALPHA) * g_ping_env.rtt.rtt_ewma))

typedef enum bool{

    false,
    true

}       bool;

typedef struct s_ping_spec
{
    u_int8_t        opts;
    u_int32_t       packetlen;
    u_int64_t       npacket;
    bool            holderr;
    bool            timestamp;
    uint8_t         ttl;
    int32_t         interval;
    struct timeval  timeout;
}               t_ping_spec; 

typedef struct      s_msg_data
{
    struct msghdr   msg_hdr;
    struct iovec    msg_iov;
}                   t_msg_data;

typedef struct                  s_cmsg_info
{
    struct sock_extended_err    *error_ptr;
    struct cmsghdr              *cmsg;
}                               t_cmsg_info;

typedef struct          s_dest_info
{
    char                *name;
    struct addrinfo     addr_info;   
    struct sockaddr     sock_addr;
    struct in_addr      bytes_addr;
}                       t_dest_info;

typedef struct          s_resolved_addr
{
    char                full_addr[ADDR_MAX_LEN];
    char                num_addr[INET_ADDRSTRLEN];
}                       t_resolved_addr;

typedef struct          s_rtt_info
{
    int                 rtt_count;
    int                 rtt_sum;
    float               rtt_min;
    float               rtt_max;
    float               rtt_ewma;
    t_list              *rtt_list;
    struct timeval      r_time;
    int                 time;
}                       t_rtt_info;

typedef struct          t_sending_info
{
    uint16_t            current_seq;
    uint32_t            packet_sent;
    uint32_t            packet_recv;
    uint32_t            error_count;
    bool                aknowledged;
    bool                recv;
    bool                stop;
}                       t_sending_info;

typedef struct          s_ping_env
{
    t_ping_spec         spec;
    t_dest_info         dest;
    t_resolved_addr     last_resolved_addr;
    t_rtt_info          rtt;
    t_sending_info      send_infos;
    int                 sockfd;
}                       t_ping_env;

extern t_ping_env       g_ping_env;

// network tools
uint16_t                my_ntohs(int16_t nshort);
uint16_t                my_htons(int16_t nshort);
uint16_t                in_cksum(uint16_t *buff, uint16_t size);

void                    get_ping_opt(int argc, char **argv);

// time functions
struct timeval          get_timeval();
struct timeval          secs_to_timeval(double secs);
float                   usec_time_diff(struct timeval start, struct timeval end);

// error functions
void                    error(uint8_t code, int err, char *err_format, ...);


// action functions
void                    send_icmp_packet(void);
void                    receive_icmp_packet(void);

// address resolution
void                    resolve_ipv4_addr(struct in_addr byte_address);
void                    get_dest_addr(char *host_name);

// rtt functions
float                   get_mdev_rtt(t_list *rtt_list, float avg_rtt);
void                    update_rtt(float rtt);
float                   add_packet_rtt(void *icmp_packet, struct timeval current_time);
void                    calculate_final_time(struct timeval current_time);

// print
void                    print_response_packet(int datalen, uint16_t sequence,
                            int ttl, int rtt, const char *err);
void                    print_err_response(uint16_t sequence, uint8_t type,
                            uint8_t code, struct ip* ip_hdr);
void                    print_icmp_err(int type, int code, struct ip* ip_hdr);
void                    print_rtt_current_stats(void);
void                    print_ping_statistics(void);
void                    print_ping_header(void);

#endif