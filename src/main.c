#include "ping.h"

uint16_t checksum(uint16_t *buff, ssize_t size)
{
    int count = size;
    uint32_t checksum = 0;

    while (count > 1)
    {
        checksum += *(buff++);
        count -= 2;
    }
    if (count)
        checksum += *(uint8_t *)buff;

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum += (checksum >> 16);

    return ~checksum;
}

struct addrinfo *get_first_valid_addrinfo(struct addrinfo *server_result)
{

    for (struct addrinfo *p = server_result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
            break;
        else if (p->ai_protocol != IPPROTO_ICMP && p->ai_protocol != IPPROTO_ICMPV6)
            break;
        else if (p->ai_addrlen != sizeof(struct sockaddr_in)
            && p->ai_addrlen != sizeof(struct sockaddr_in6))
            break;
        else if (p->ai_socktype != SOCK_RAW)
            break;
        else if (p->ai_addr == NULL)
            break;
        else
            return p;
    }
    return NULL;
}

void handle_error(char *msg, short exit_code, bool condition)
{
    if (condition)
    {
        perror(msg);
        exit(exit_code);
    }
}

int get_socketfd(int domain, int type, int protocol)
{
    int sockfd;

    handle_error("Error in socket.", 1, (sockfd = socket(domain, type, protocol)) == -1);
    return sockfd;
}

struct sockaddr_in* get_sockaddr_in(struct in_addr addr)
{
    struct sockaddr_in *sock_addr;

    sock_addr = (struct sockaddr_in *)calloc(sizeof(struct sockaddr_in), 1);
    sock_addr->sin_family = AF_INET;
    sock_addr->sin_addr = addr;
    return sock_addr;
}

struct sockaddr_in6* get_sockaddr_in6(struct in6_addr addr)
{
    struct sockaddr_in6* sock_addr;

    sock_addr = (struct sockaddr_in6 *)calloc(sizeof(struct sockaddr_in6), 1);
    sock_addr->sin6_family = AF_INET6;
    sock_addr->sin6_addr = addr;
    return sock_addr;
}

void fill_icmp_packet(char *packet_buffer, int packet_len, int seq)
{
    struct icmp *icmp_header;
    
    icmp_header = (struct icmp *)packet_buffer;
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_seq = seq;
    icmp_header->icmp_id = getpid();
    icmp_header->icmp_cksum = checksum((uint16_t *)packet_buffer, packet_len);
}

struct msghdr create_message_header(void* message_buffer, int message_len)
{
    struct msghdr  msg;

    msg.msg_iov->iov_base = message_buffer;
    msg.msg_iov->iov_len = message_len;
    msg.msg_iovlen = 1;
    return msg;
}

struct timeval get_timeval()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv;
}

float get_time_diff(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
}

void read_packet_message(void *message_buffer, int original_packet_len)
{
    struct ip   *ip_header;
    struct icmp *icmp_header;

    int i = -1;
    char *message = (char *)message_buffer;

    ip_header = (struct ip *)message;
    if (ip_header->ip_p != IPPROTO_ICMP)
        return;
    icmp_header = (struct icmp *)(message + sizeof(struct ip));
    if (icmp_header->icmp_type != ICMP_ECHOREPLY)
        return;
    printf("Packet received: %d\n", icmp_header->icmp_seq);
}

void send_icmp_packet(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len, int seq)
{
    char            packet_buffer[packet_len];
    char            recv_buffer[ICMP_HDR_LEN + packet_len];
    struct msghdr   msg;

    
    memset(packet_buffer, 0, sizeof(packet_buffer));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    msg = create_message_header(recv_buffer, sizeof(recv_buffer));
    fill_icmp_packet(packet_buffer, packet_len, seq);
    handle_error("Error in sendto", 1, sendto(sockfd, packet_buffer, sizeof(packet_buffer), 0, dest_addr, dest_addr_len) == -1);
    printf("Packet sent: %d\n", seq);
    if (recvmsg(sockfd, &msg, 0))
        read_packet_message(recv_buffer, packet_len);
}


bool g_sending = true;

void unlock_sending(int signum)
{
    g_sending = true;
}

void ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len)
{
    int seq = 1;

    signal(SIGALRM, unlock_sending);
    for (;;)
    {
        if (g_sending)
        {
            send_icmp_packet(sockfd, dest_addr, dest_addr_len, packet_len, seq);
            g_sending = false;
            seq++;
            alarm(1);
        }
        usleep(42);
    }
}

struct sockaddr* get_sockaddr(struct addrinfo *addrinfo)
{
    struct sockaddr *sockaddr;

    if (addrinfo->ai_family == AF_INET)
    {
        struct sockaddr_in *sockaddr_v4 = (struct sockaddr_in *)addrinfo->ai_addr;
        sockaddr = (struct sockaddr *)get_sockaddr_in(sockaddr_v4->sin_addr);
    }
    else if (addrinfo->ai_family == AF_INET6)
    {
        struct sockaddr_in6 *sockaddr_v6 = (struct sockaddr_in6 *)addrinfo->ai_addr;
        sockaddr = (struct sockaddr *)get_sockaddr_in6(sockaddr_v6->sin6_addr);
    }
    return sockaddr;
}

int main(int argc, char **argv)
{
    struct addrinfo hints;
    struct addrinfo *server_result;
    struct addrinfo *dest_addrinfo;
    struct sockaddr *socket_address;

    memset(&hints, 0, sizeof(hints));
    hints = (struct addrinfo){ .ai_family = AF_UNSPEC,
                        .ai_socktype = SOCK_RAW,
                        .ai_protocol = IPPROTO_ICMP,
                        .ai_flags = AI_PASSIVE };

    handle_error("First argument unfound", 1, argc != 2);
    handle_error("Error in getaddrinfo", 1, !!(getaddrinfo(argv[1], NULL, &hints, &server_result)));

    dest_addrinfo = get_first_valid_addrinfo(server_result);
    handle_error("Error in getaddrinfo", 1, dest_addrinfo == NULL);

    int sockfd = get_socketfd(dest_addrinfo->ai_family, SOCK_RAW, IPPROTO_ICMP);
    handle_error("Error in socket", 1, sockfd == -1);

    socket_address = get_sockaddr(dest_addrinfo);

    ping_routine(sockfd, socket_address, dest_addrinfo->ai_addrlen, PACKET_SIZE);
    
    freeaddrinfo(server_result);
    return 0;
}