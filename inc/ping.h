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


#define PACKET_SIZE 56
#define MAX_PACKET_SIZE 65536


#define ICMP_HDR_LEN 8
#define IP_HDR_LEN 20

#define DEFAULT_TTL 64

typedef enum bool
{
    false,
    true
}            bool;

typedef struct  s_ping_stats
{
    int         packet_sent_nbr;
    int         packet_recv_nbr;

    float       min_packet_delay;
    float       max_packet_delay;

    bool        sending_status;

    char       *host_name;

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
void                    read_packet_message(void *message_buffer, int original_packet_len, float time_diff);

uint16_t                checksum(uint16_t *buff, ssize_t size);
int                     get_socketfd(int domain, int type, int protocol);
float                   get_time_diff(struct timeval start, struct timeval end);
#endif