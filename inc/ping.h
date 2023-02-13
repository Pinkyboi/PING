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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <math.h>

#define ICMP_HDR_LEN 8
#define IP_HDR_LEN 20
#define C_DATA_LEN 521

#define MAX_TTL 1024
#define MAX_TIMEOUT 2147483
#define MAX_INTERVAL 2147483
#define MAX_PACKET_COUNT 2147483647
#define MAX_PACKET_SIZE 65527

#define DEFAULT_TTL 64

#define DEFAULT_TIMEOUT_SEC 4

#define DEFAULT_INTERVAL 1
#define DEFAULT_TTL 64
#define DEFAUL_TPACKET_SIZE 56

#define HOST_NAME_MAX 256

#define H_OPTION (1 << (0))
#define V_OPTION (1 << (1))
#define C_OPTION (1 << (2))
#define S_OPTION (1 << (3))
#define N_OPTION (1 << (4))
#define I_OPTION (1 << (5))
#define W_OPTION (1 << (6))
#define T_OPTION (1 << (7))


#define SOCKET_ERROR -1
#define SOCKET_SUCCESS 1
 
typedef enum bool
{
    false,
    true
}            bool;

typedef struct s_packet_node
{
    int                     seq;
    float                   rtt;
    struct timeval          send_time;
    struct timeval          recv_time;
    struct s_packet_node    *next;
}               t_packet_node;

typedef struct s_rtt_info
{
    float           rtt_count;
    float           rtt_sum;
    float           rtt_min;
    float           rtt_max;
    t_packet_node   *packet_list;
}               t_rtt_info;

typedef struct  s_msg_data
{
    struct msghdr  msg_hdr;
    struct iovec   msg_iov;
}               t_msg_data;

typedef struct s_cmsg_info
{
    struct sock_extended_err    *error_ptr;
    struct cmsghdr              *cmsg;
}               t_cmsg_info;

typedef struct      s_ping_spec
{
    u_int8_t        options;
    struct timeval  timeout;
    bool            hold_err;
    int             max_packet;
    int             packet_size;
    int             ttl;
    int             interval;
    char            resolved_hostname[HOST_NAME_MAX];
    char            resolved_hostname_ip[INET6_ADDRSTRLEN];
    char            *unresolved_hostname;
}                   t_ping_spec;

typedef struct      s_ping_stats
{
    int             packet_sent_nbr;
    int             packet_recv_nbr;
    bool            sending_status;
    struct timeval  start_time;
    t_rtt_info      rtt_info;
    t_ping_spec     specs;
}                   t_ping_stats;



struct sockaddr*        get_sockaddr(struct addrinfo *addrinfo);
struct sockaddr_in*     get_sockaddr_in(struct in_addr addr);
struct addrinfo*        get_first_valid_addrinfo(struct addrinfo *server_result);
// t_msg_data              create_message_header(void* message_header, int message_len);
struct timeval          get_timeval();

void                    send_icmp_packet(int sockfd, struct sockaddr *dest_addr,
                            int dest_addr_len, int packet_len, int seq);
void                    unlock_sending(int signum);
void                    handle_error(char *msg, short exit_code);
void                    ping_routine(int sockfd, struct sockaddr *dest_addr,
                            int dest_addr_len, int packet_len);

t_packet_node           *read_packet_message(void *message_buffer, t_packet_node *packet_list, struct timeval recv_time);


t_packet_node           *get_packet_node(t_packet_node *packet_list, int seq);
uint16_t                checksum(uint16_t *buff, ssize_t size);
int                     get_socketfd(int domain, int type, int protocol);
float                   get_time_diff(struct timeval start, struct timeval end);



float pow_2(float x);
float newtonian_sqrt(float x, float precision);
#endif