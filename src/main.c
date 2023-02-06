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
    printf("%s: %s\n", msg, strerror(errno));
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

float get_rtt_time(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
}

void add_rtt_node(t_rtt_node **rtt_list, float rtt)
{
    t_rtt_node *new_node;

    new_node = (t_rtt_node *)malloc(sizeof(t_rtt_node));
    new_node->rtt = rtt;
    new_node->next = NULL;
    if (*rtt_list != NULL)
        new_node->next = *rtt_list;
    *rtt_list = new_node;
}

float get_standard_deviation_rtt(t_rtt_node *rtt_list, float average_rtt)
{
    float variance = 0;
    int rtt_count = 0;

    for(t_rtt_node *p = rtt_list; p != NULL; p = p->next)
    {
        variance += pow(p->rtt - average_rtt, 2);
        rtt_count++;
    }
    return sqrt(variance / rtt_count);
}


void print_packet_recipe(struct ip* ip_header, struct icmp *icmp_header, float time_diff)
{

    printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.3f ms\n",
        ip_header->ip_len,
        g_ping_stats.host_name,
        icmp_header->icmp_seq,
        ip_header->ip_ttl,
        time_diff);
}

bool read_packet_message(void *message_buffer, int original_packet_len, float time_diff)
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

    if (icmp_header->icmp_id == getpid())
    {
        print_packet_recipe(ip_header, icmp_header, time_diff);
        return true;
    }
    return false;
}

void update_rtt_info(t_rtt_info *rtt_info, float new_rtt)
{
    rtt_info->rtt_count++;
    rtt_info->rtt_sum += new_rtt;
    if (rtt_info->rtt_min > new_rtt || rtt_info->rtt_min == 0)
        rtt_info->rtt_min = new_rtt;
    if (rtt_info->rtt_max < new_rtt)
        rtt_info->rtt_max = new_rtt;
    add_rtt_node(&rtt_info->rtt_list, new_rtt);
}


void receive_icmp_packet(int sockfd, int packet_len, struct timeval send_time)
{
    char            recv_buffer[IP_HDR_LEN + ICMP_HDR_LEN + packet_len];
    struct msghdr   *msg;

    memset(recv_buffer, 0, sizeof(recv_buffer));
    msg = create_message_header(recv_buffer, sizeof(recv_buffer));
    while (recvmsg(sockfd, msg, 0))
    {
        float current_rtt = get_rtt_time(send_time, get_timeval());
        if (read_packet_message(recv_buffer, packet_len, current_rtt))
        {
            update_rtt_info(&g_ping_stats.rtt_info, current_rtt);
            g_ping_stats.packet_recv_nbr++;
            break;
        }
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

void print_rtt_infos(t_rtt_info rtt_info)
{
    float average_rtt = rtt_info.rtt_sum / rtt_info.rtt_count;
    float standard_deviation_rtt = get_standard_deviation_rtt(rtt_info.rtt_list, average_rtt);

    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
        rtt_info.rtt_min, average_rtt, rtt_info.rtt_max, standard_deviation_rtt);
}
void print_packet_statistics(int packet_sent_nbr, int packet_recv_nbr)
{
    float packet_lost = fractional_percentage(packet_sent_nbr - packet_recv_nbr, packet_sent_nbr);

    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
            packet_sent_nbr, packet_recv_nbr, packet_lost);
}

void print_ping_statistics(int signnum)
{
    printf("\n--- %s ping statistics ---\n", g_ping_stats.host_name);
    print_packet_statistics(g_ping_stats.packet_sent_nbr, g_ping_stats.packet_recv_nbr);
    print_rtt_infos(g_ping_stats.rtt_info);
    exit(0);
}

void ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len)
{
    int seq = 0;

    signal(SIGALRM, unlock_sending);
    signal(SIGINT, print_ping_statistics);
    while (1)
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

struct addrinfo* get_host_addrinfo(char *host_name)
{
    struct addrinfo hints;
    struct addrinfo *server_result;

    memset(&hints, 0, sizeof(hints));
    hints = (struct addrinfo){.ai_socktype = SOCK_RAW,
                                .ai_protocol = IPPROTO_ICMP};

    int status = getaddrinfo(host_name, NULL, &hints, &server_result);
    if (status)
        gai_strerror(status);
    return server_result;
}


int main(int argc, char **argv)
{
    int             sockfd;
    struct addrinfo *server_result;
    struct addrinfo *dest_addrinfo;
    struct sockaddr *socket_address;


    if (argc != 2)
        handle_error("First argument unfound", 1);

    server_result = get_host_addrinfo(argv[1]);

    dest_addrinfo = get_first_valid_addrinfo(server_result);

    if (dest_addrinfo == NULL)
        handle_error("Error in getaddrinfo", 1);

    sockfd = socket(dest_addrinfo->ai_family, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
        handle_error("Error in socket", 1);

    socket_address = get_sockaddr(dest_addrinfo);

    g_ping_stats.sending_status = true;
    getnameinfo(dest_addrinfo->ai_addr, dest_addrinfo->ai_addrlen, g_ping_stats.host_name, sizeof(g_ping_stats.host_name), NULL, 0, 0);

    
    ping_routine(sockfd, socket_address, dest_addrinfo->ai_addrlen, PACKET_SIZE);
    
    freeaddrinfo(server_result);
    return 0;
}