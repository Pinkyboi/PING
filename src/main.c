#include "ping.h"

t_ping_stats    g_ping_stats;

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

void handle_error(char *msg, short exit_code)
{
    perror(msg);
    exit(exit_code);
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

struct msghdr *create_message_header(void* message_buffer, int message_len)
{
    struct msghdr   *msg;
    struct msghdr   *iov;

    msg = (struct msghdr *)calloc(sizeof(struct msghdr), 1);
    msg->msg_iov = (struct iovec *)calloc(sizeof(struct iovec), 1);
    msg->msg_iov->iov_base = message_buffer;
    msg->msg_iov->iov_len = message_len;
    msg->msg_iovlen = 1;
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

void print_packet_recipe(struct ip* ip_header, struct icmp *icmp_header, float time_diff)
{
    char ip_addr[INET6_ADDRSTRLEN];

    inet_ntop((ip_header->ip_v == 4) ? AF_INET : AF_INET6, &ip_header->ip_src, ip_addr, sizeof(ip_addr));
    printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.3f ms\n",
        ip_header->ip_len,
        ip_addr,
        icmp_header->icmp_seq,
        ip_header->ip_ttl,
        time_diff);
}

void read_packet_message(void *message_buffer, int original_packet_len, float time_diff)
{
    struct ip   *ip_header;
    struct icmp *icmp_header;

    int i = -1;
    char *message = (char *)message_buffer;

    ip_header = (struct ip *)message;
    if (ip_header->ip_p != IPPROTO_ICMP)
        handle_error("Invalid protocol", 1);
    icmp_header = (struct icmp *)(message + (ip_header->ip_hl << 2));
    if (icmp_header->icmp_type != ICMP_ECHOREPLY)
        handle_error("Invalid type", 1);
    if (checksum((uint16_t *)icmp_header, original_packet_len) != 0)
        handle_error("(BAD CHECKSUM)", 1);

    print_packet_recipe(ip_header, icmp_header, time_diff);
}


void receive_icmp_packet(int sockfd, int packet_len, struct timeval send_time)
{
    char            recv_buffer[IP_HDR_LEN + ICMP_HDR_LEN + packet_len];
    struct msghdr   *msg;

    memset(recv_buffer, 0, sizeof(recv_buffer));
    msg = create_message_header(recv_buffer, sizeof(recv_buffer));
    if (recvmsg(sockfd, msg, 0))
    {
        read_packet_message(recv_buffer, packet_len, get_time_diff(send_time, get_timeval()));
        g_ping_stats.packet_recv_nbr++;
    }
    free(msg->msg_iov);
    free(msg);
}

void send_icmp_packet(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len, int seq)
{
    char            packet_buffer[ICMP_HDR_LEN + packet_len];
    struct timeval  send_time;
    struct timeval  recv_time;

    memset(packet_buffer, 0, sizeof(packet_buffer));
    fill_icmp_packet(packet_buffer, packet_len, seq);
    if (sendto(sockfd, packet_buffer, sizeof(packet_buffer), 0, dest_addr, dest_addr_len) == -1)
        handle_error("Error in sendto", 1);
    send_time = get_timeval();
    g_ping_stats.packet_sent_nbr++;
    receive_icmp_packet(sockfd, packet_len, send_time);
    recv_time = get_timeval();
}

float fractional_percentage(float numerator, float denominator)
{
    return (numerator / denominator) * 100.0;
}

void unlock_sending(int signum)
{
    g_ping_stats.sending_status = true;
}

void print_ping_statistics(int signnum)
{
    float packet_lost = fractional_percentage(g_ping_stats.packet_sent_nbr - g_ping_stats.packet_recv_nbr, g_ping_stats.packet_sent_nbr);
    
    printf("\n--- %s ping statistics ---\n", g_ping_stats.host_name);
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
            g_ping_stats.packet_sent_nbr, g_ping_stats.packet_sent_nbr, packet_lost);
    exit(0);
}

void ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len)
{
    int seq = 1;

    signal(SIGALRM, unlock_sending);
    signal(SIGINT, print_ping_statistics);
    for (;;)
    {
        if (g_ping_stats.sending_status)
        {
            send_icmp_packet(sockfd, dest_addr, dest_addr_len, packet_len, seq);
            g_ping_stats.sending_status = false;
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
    int             sockfd;
    struct addrinfo hints;
    struct addrinfo *server_result;
    struct addrinfo *dest_addrinfo;
    struct sockaddr *socket_address;

    memset(&hints, 0, sizeof(hints));
    hints = (struct addrinfo){.ai_socktype = SOCK_RAW,
                                .ai_protocol = IPPROTO_ICMP};

    if (argc != 2)
        handle_error("First argument unfound", 1);
    if (getaddrinfo(argv[1], NULL, &hints, &server_result) != 0)
        handle_error("Error in getaddrinfo", 1);

    dest_addrinfo = get_first_valid_addrinfo(server_result);
    if (dest_addrinfo == NULL)
        handle_error("Error in getaddrinfo", 1);

    sockfd = socket(dest_addrinfo->ai_family, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
        handle_error("Error in socket", 1);

    socket_address = get_sockaddr(dest_addrinfo);

    g_ping_stats.sending_status = true;
    g_ping_stats.host_name = argv[1];
    
    ping_routine(sockfd, socket_address, dest_addrinfo->ai_addrlen, PACKET_SIZE);
    
    freeaddrinfo(server_result);
    return 0;
}