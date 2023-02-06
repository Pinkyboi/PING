#ifndef __PING_H__
#define __PING_H__

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
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define PACKET_SIZE 56

#define ICMP_HDR_LEN 8
#define IP_HDR_LEN 20

#define DEFAULT_TTL 64

#define HOST_NAME_MAX 256

#define POW2(X) X * X

typedef enum bool
{
    false,
    true
}            bool;

typedef struct s_rtt_node
{
    float               rtt;
    struct s_rtt_node   *next;
}               t_rtt_node;

typedef struct s_rtt_info
{
    float       rtt_count;
    float       rtt_sum;
    float       rtt_min;
    float       rtt_max;
    t_rtt_node  *rtt_list;
}               t_rtt_info;


typedef struct  s_ping_stats
{
    int         packet_sent_nbr;
    int         packet_recv_nbr;
    char        host_name[HOST_NAME_MAX];
    t_rtt_info  rtt_info;
    bool        sending_status;

}               t_ping_stats;


struct sockaddr*        get_sockaddr(struct addrinfo *addrinfo);
struct sockaddr_in*     get_sockaddr_in(struct in_addr addr);
struct sockaddr_in6*    get_sockaddr_in6(struct in6_addr addr);
struct addrinfo*        get_first_valid_addrinfo(struct addrinfo *server_result);
struct msghdr*          create_message_header(void* message_header, int message_len);
struct timeval          get_timeval();

void                    send_icmp_packet(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len, int seq);
void                    unlock_sending(int signum);
void                    handle_error(char *msg, short exit_code);
void                    ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len);
bool                    read_packet_message(void *message_buffer, int original_packet_len, float time_diff);

uint16_t                checksum(uint16_t *buff, ssize_t size);
int                     get_socketfd(int domain, int type, int protocol);
float                   get_time_diff(struct timeval start, struct timeval end);
#endif