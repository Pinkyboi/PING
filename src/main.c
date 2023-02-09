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
        if (p->ai_family != AF_INET)
            continue;
        else if (p->ai_protocol != IPPROTO_ICMP)
            continue;
        else if (p->ai_addrlen != sizeof(struct sockaddr_in))
            continue;
        else if (p->ai_socktype != SOCK_RAW)
            continue;
        else if (p->ai_addr == NULL)
            continue;
        else
            return p;
    }
    return NULL;
}

void handle_error(char *msg, short exit_code)
{
    if (errno)
        printf("%s: %s\n", msg, strerror(errno));
    else
        printf("%s\n", msg);
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

float get_standard_deviation_rtt(t_packet_node *packet_list, float average_rtt)
{
    float variance = 0;
    int rtt_count = 0;

    for(t_packet_node *p = packet_list; p != NULL; p = p->next)
    {
        variance += pow(p->rtt - average_rtt, 2);
        rtt_count++;
    }
    return sqrt(variance / rtt_count);
}


void print_packet_recipe(struct ip* ip_header, struct icmp *icmp_header, float time_diff)
{
    printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.3f ms",
        ip_header->ip_len,
        g_ping_stats.specs.resolved_hostname,
        icmp_header->icmp_seq,
        ip_header->ip_ttl,
        time_diff);
}

void print_ip_hdr(struct ip* ip_hdr)
{
    return;    
}

void icmphdr_errors(int type, int code, struct ip* ip_hdr)
{
    if (type == ICMP_ECHOREPLY)
    {
        if (type == ICMP_UNREACH)
        {
            if (code == ICMP_UNREACH_NET)
                printf("Destination Net Unreachable\n");
            else if (code == ICMP_UNREACH_HOST)
                printf("Destination Host Unreachable\n");
            else if (code == ICMP_UNREACH_PROTOCOL)
                printf("Destination Protocol Unreachable\n");
            else if (code == ICMP_UNREACH_PORT)
                printf("Destination Port Unreachable\n");
            else if (code == ICMP_UNREACH_NEEDFRAG)
                printf("Fragmentation Needed and DF Set\n");
            else if (code == ICMP_UNREACH_SRCFAIL)
                printf("Source Route Failed\n");
            else if (code == ICMP_UNREACH_NET_UNKNOWN)
                printf("Destination Network Unknown\n");
            else if (code == ICMP_UNREACH_HOST_UNKNOWN)
                printf("Destination Host Unknown\n");
            else if (code == ICMP_UNREACH_ISOLATED)
                printf("Source Host Isolated\n");
            else if (code == ICMP_UNREACH_NET_PROHIB)
                printf("Communication with Destination Network is Administratively Prohibited\n");
            else if (code == ICMP_UNREACH_HOST_PROHIB)
                printf("Communication with Destination Host is Administratively Prohibited\n");
            else if (code == ICMP_UNREACH_TOSNET)
                printf("Destination Network Unreachable for Type of Service\n");
            else if (code == ICMP_UNREACH_TOSHOST)
                printf("Destination Host Unreachable for Type of Service\n");
            else if (code == ICMP_UNREACH_FILTER_PROHIB)
                printf("Communication Administratively Prohibited\n");
            else if (code == ICMP_UNREACH_HOST_PRECEDENCE)
                printf("Host Precedence Violation\n");
            else if (code == ICMP_UNREACH_PRECEDENCE_CUTOFF)
                printf("Precedence cutoff in effect\n");
            else
            {
                printf("Destination Unreachable, Bad Code %d\n", code);
                if (g_ping_stats.specs.options & V_OPTION)
                    print_ip_hdr(ip_hdr);
            }
        }
        else if (type == ICMP_TIMXCEED)
        {
            if (code == ICMP_TIMXCEED_INTRANS)
                printf("Time to Live Exceeded in Transit\n");
            else if (code == ICMP_TIMXCEED_REASS)
                printf("Fragment Reassembly Time Exceeded\n");
            else
            {
                printf("Time Exceeded, Bad Code %d\n", code);
                if (g_ping_stats.specs.options & V_OPTION)
                    print_ip_hdr(ip_hdr);
            }
        }
        else if (type == ICMP_SOURCEQUENCH)
            printf("Source Quench\n");
        else if (type == ICMP_PARAMPROB)
            printf("Parameter Problem\n");
        else if (type == ICMP_REDIRECT)
        {
            if (code == ICMP_REDIRECT_NET)
                printf("Redirect Datagram for the Network\n");
            else if (code == ICMP_REDIRECT_HOST)
                printf("Redirect Datagram for the Host\n");
            else if (code == ICMP_REDIRECT_TOSNET)
                printf("Redirect Datagram for the Type of Service and Network\n");
            else
            {
                printf("Redirect, Bad Code: %d\n", code);
                if (g_ping_stats.specs.options & V_OPTION)
                    print_ip_hdr(ip_hdr);
            }
        }
        else
            printf("\n");
    }
    else
    {
        printf("Bad ICMP type: %d\n", type);
        if (g_ping_stats.specs.options & V_OPTION)
            print_ip_hdr(ip_hdr);
    }
}

bool check_seq_occurence(t_packet_node *recv_seq_list, int seq)
{
    return false;
}

void print_hdr_errors(struct icmp*icmp_hdr, struct ip*ip_hdr)
{
    if (checksum((uint16_t *)icmp_hdr, ip_hdr->ip_len) != 0)
        printf("(BAD CHECKSUM)\n");
    else
        icmphdr_errors(icmp_hdr->icmp_type, icmp_hdr->icmp_code, ip_hdr);
}

t_packet_node *read_packet_message(void *message_buffer, int original_packet_len,
    t_packet_node *packet_list, struct timeval recv_time)
{
    struct ip       *ip_hdr;
    struct icmp     *icmp_hdr;
    t_packet_node   *packet_node;

    ip_hdr = (struct ip *)message_buffer;
    icmp_hdr = (struct icmp *)(message_buffer + (ip_hdr->ip_hl << 2));
    if (icmp_hdr->icmp_id != getpid())
        return NULL;
    packet_node = get_packet_node(packet_list, icmp_hdr->icmp_seq);
    if (!packet_node->rtt)
    {
        packet_node->recv_time = recv_time;
        print_packet_recipe(ip_hdr, icmp_hdr, get_time_diff(packet_node->send_time,
            packet_node->recv_time));
        print_hdr_errors(icmp_hdr, ip_hdr);
        return packet_node;
    }
    else
    {
        print_packet_recipe(ip_hdr, icmp_hdr, get_time_diff(packet_node->send_time,
            recv_time));
        printf("(DUP)\n");
    }
    return NULL;
}

void update_rtt_info(t_rtt_info *rtt_info, struct timeval start_time, struct timeval end_time)
{
    int     new_rtt;

    new_rtt = get_time_diff(start_time, end_time);
    rtt_info->rtt_count++;
    rtt_info->rtt_sum += new_rtt;
    if (rtt_info->rtt_min > new_rtt || rtt_info->rtt_min == 0)
        rtt_info->rtt_min = new_rtt;
    if (rtt_info->rtt_max < new_rtt)
        rtt_info->rtt_max = new_rtt;
}

int get_icmp_seq(void *message_buffer)
{
    struct ip       *ip_hdr;
    struct icmp     *icmp_hdr;
    
    ip_hdr = (struct ip *)message_buffer;
    icmp_hdr = (struct icmp*)(message_buffer + (ip_hdr->ip_hl  <<  2));

    return icmp_hdr->icmp_seq;    
}

void receive_icmp_packet(int sockfd, int packet_len)
{
    char                    recv_buffer[IP_HDR_LEN + ICMP_HDR_LEN + packet_len];
    struct msghdr           *msg;
    t_packet_node           *packet_node;
    struct timeval          recv_time;
    int8_t                  recv_status;

    memset(recv_buffer, 0, sizeof(recv_buffer));
    msg = create_message_header(recv_buffer, sizeof(recv_buffer));
    if(recvmsg(sockfd, msg, MSG_WAITALL))
    {
        recv_time = get_timeval();
        packet_node = read_packet_message(recv_buffer, packet_len,
            g_ping_stats.rtt_info.packet_list, recv_time);
        if (packet_node != NULL)
        {
            packet_node->recv_time = get_timeval();
            update_rtt_info(&g_ping_stats.rtt_info, packet_node->send_time,
                packet_node->recv_time);
            g_ping_stats.packet_recv_nbr++;
        }
    }
    if (errno == EWOULDBLOCK)
        printf("Request timeout for icmp_seq %d\n", g_ping_stats.packet_sent_nbr - 1);
}

void add_packet_node(t_packet_node **packet_list, struct timeval send_time,
    struct timeval recv_time, int seq)
{
    t_packet_node *new_node;
    float         rtt;

    new_node = (t_packet_node *)malloc(sizeof(t_packet_node));
    new_node->seq = seq;
    new_node->send_time = send_time;
    new_node->recv_time = recv_time;
    new_node->rtt = 0;
    new_node->next = NULL;
    if (*packet_list != NULL)
        new_node->next = *packet_list;
    *packet_list = new_node;
}

t_packet_node *get_packet_node(t_packet_node *packet_list, int seq)
{
    t_packet_node *list_head;

    list_head = packet_list;
    while(list_head)
    {
        if (list_head->seq == seq)
            return list_head;
    }
    return NULL;
}

void send_icmp_packet(int sockfd, struct sockaddr *dest_addr,
                        int dest_addr_len, int packet_len, int seq)
{
    char            packet_buffer[ICMP_HDR_LEN + packet_len];
    struct timeval  send_time;
    int8_t          sendto_status;

    memset(packet_buffer, 0, sizeof(packet_buffer));
    fill_icmp_packet(packet_buffer, packet_len, seq);
    send_time = get_timeval();
    sendto_status = sendto(sockfd, packet_buffer,
        sizeof(packet_buffer), 0, dest_addr, dest_addr_len);
    if (sendto_status)
    {
        if (sendto_status == SOCKET_ERROR && errno == ETIMEDOUT)
            printf("Request timeout for icmp_seq %d\n", seq);
        else
        {
            add_packet_node(&g_ping_stats.rtt_info.packet_list,
                send_time, (struct timeval){0, 0}, seq);
            g_ping_stats.packet_sent_nbr++;
        }
    }
}

float fractional_percentage(float numerator, float denominator)
{
    return (numerator / denominator) * 100.0;
}

void unlock_sending(int signum)
{
    g_ping_stats.sending_status = true;
}

void print_rtt_infos(int signnum)
{
    t_rtt_info rtt_info = g_ping_stats.rtt_info;
    float average_rtt = rtt_info.rtt_sum / rtt_info.rtt_count;
    float standard_deviation_rtt = get_standard_deviation_rtt(rtt_info.packet_list, average_rtt);

    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
        rtt_info.rtt_min, average_rtt, rtt_info.rtt_max, standard_deviation_rtt);
}
void print_packet_statistics(int packet_sent_nbr, int packet_recv_nbr)
{
    float packet_lost = fractional_percentage(packet_sent_nbr - packet_recv_nbr, packet_sent_nbr);
    float time_passed = get_time_diff(g_ping_stats.start_time, get_timeval());

    printf("%d packets transmitted, %d packets received, %.1f%% packet loss, time %.3fms\n",
            packet_sent_nbr, packet_recv_nbr, packet_lost, time_passed);
}

void print_ping_statistics(int signnum)
{
    printf("\n--- %s ping statistics ---\n", g_ping_stats.specs.resolved_hostname);
    print_packet_statistics(g_ping_stats.packet_sent_nbr, g_ping_stats.packet_recv_nbr);
    if (g_ping_stats.packet_recv_nbr)
        print_rtt_infos(signnum);
    exit(0);
}

void ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len)
{
    int             seq;

    seq = 0;
    signal(SIGALRM, unlock_sending);
    signal(SIGINT, print_ping_statistics);
    while (true)
    {
        if (g_ping_stats.sending_status)
        {
            send_icmp_packet(sockfd, dest_addr, dest_addr_len, packet_len, seq);
            g_ping_stats.sending_status = false;
            receive_icmp_packet(sockfd, packet_len);
            seq++;
            if (g_ping_stats.specs.options & C_OPTION && seq == g_ping_stats.specs.max_packet)
                print_ping_statistics(0);
            alarm(g_ping_stats.specs.interval);
        }
        usleep(42);
    }
}

struct sockaddr* get_sockaddr(struct addrinfo *addrinfo)
{
    struct sockaddr *sockaddr;

    sockaddr = NULL;
    if (addrinfo->ai_family == AF_INET)
    {
        struct sockaddr_in *sockaddr_v4 = (struct sockaddr_in *)addrinfo->ai_addr;
        sockaddr = (struct sockaddr *)get_sockaddr_in(sockaddr_v4->sin_addr);
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

void pingv4_usage(void)
{
    printf("\nUsage\n  ping [options] <destination>\n");
    printf("\nOptions:\n");
    printf("  <destination>      dns name or ip address\n");
    printf("  -h                 print help and exit\n");
    printf("  -v                 verbose output\n");
    printf("  -n                 no dns name resolution\n");
    printf("  -i <interval>      seconds between sending each packet\n");
    printf("  -s <size>          use <size> as number of data bytes to be sent\n");
    printf("  -t <ttl>           define time to live\n");
    printf("  -W <timeout>       time to wait for response\n");
    printf("  -c <count>         stop after sending <count> ECHO_REQUEST packets\n");
    exit(2);
}

int get_option_num_arg(char *argument, int max_value, char *option)
{
    int option_num_arg;

    if (argument == NULL)
    {
        printf("ping: option requires an argument -- '%s'", option);
        pingv4_usage();
    }
    option_num_arg = atoi(argument);
    if (option_num_arg <= 0 || option_num_arg > max_value)
    {
        printf("ping: invalid argument '%s' out of range: 0 < value <= %d",
            argument, max_value);
        pingv4_usage();
    }
    return option_num_arg;
}

void set_flags(char **prog_arg)
{
    int i = -1;
    char *argument;

    while(prog_arg[++i])
    {
        if (*prog_arg[i] == '-')
        {
            if (!strcmp(prog_arg[i], "-v"))
                g_ping_stats.specs.options |= V_OPTION;
            else if (!strcmp(prog_arg[i], "-h"))
                pingv4_usage();
            else if (!strcmp(prog_arg[i], "-n"))
                g_ping_stats.specs.options |= N_OPTION;

            else if (!strncmp(prog_arg[i], "-i", 2))
            {
                g_ping_stats.specs.options |= I_OPTION;
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    i++;
                }
                g_ping_stats.specs.interval = get_option_num_arg(argument, MAX_INTERVAL, "-i");
            }

            else if (!strncmp(prog_arg[i], "-c", 2))
            {
                g_ping_stats.specs.options |= C_OPTION;
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    i++;
                }
                g_ping_stats.specs.max_packet = get_option_num_arg(argument, MAX_PACKET_COUNT, "-c");
            }
            else if (!strncmp(prog_arg[i], "-s", 2))
            {
                g_ping_stats.specs.options |= S_OPTION;
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    i++;
                }
                g_ping_stats.specs.packet_size = get_option_num_arg(argument, MAX_PACKET_SIZE, "-s");
            }
            else if (!strncmp(prog_arg[i], "-W", 2))
            {
                g_ping_stats.specs.options |= W_OPTION;
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    i++;
                }
                g_ping_stats.specs.timeout.tv_sec = get_option_num_arg(argument, MAX_TIMEOUT, "-W");
            }
            else if (!strncmp(prog_arg[i], "-t", 2))
            {
                g_ping_stats.specs.options |= T_OPTION;
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    i++;
                }
                g_ping_stats.specs.ttl = get_option_num_arg(argument, MAX_TTL, "-t");
            }
            else
            {
                printf("ping: unknown option -- %s\n", prog_arg[i]);
                pingv4_usage();
            }
        }
        else if (g_ping_stats.specs.unresolved_hostname == NULL)
            g_ping_stats.specs.unresolved_hostname = prog_arg[i];
        else
        {
            printf("%s\n",prog_arg[i]);
            pingv4_usage();
        }
    }
}


void setup_ping(void)
{
    g_ping_stats.sending_status = true;
    g_ping_stats.start_time = get_timeval();
    g_ping_stats.specs.packet_size = DEFAUL_TPACKET_SIZE;
    g_ping_stats.specs.unresolved_hostname = NULL;
    g_ping_stats.specs.max_packet = -1;
    g_ping_stats.specs.options = 0;
    g_ping_stats.specs.interval = DEFAULT_INTERVAL;
    g_ping_stats.specs.timeout = (struct timeval){.tv_sec = DEFAULT_TIMEOUT_SEC, 0};
    g_ping_stats.specs.ttl = DEFAULT_TTL;
}

int main(int argc, char **argv)
{
    int             sockfd;
    struct addrinfo *server_result;
    struct addrinfo *dest_addrinfo;
    struct sockaddr *socket_address;

    if (argc < 2)
        pingv4_usage();

    setup_ping();
    set_flags(&argv[1]);
    server_result = get_host_addrinfo(g_ping_stats.specs.unresolved_hostname);
    dest_addrinfo = get_first_valid_addrinfo(server_result);

    if (dest_addrinfo == NULL)
        handle_error("Error in getaddrinfo", 1);

    sockfd = socket(dest_addrinfo->ai_family, SOCK_RAW, IPPROTO_ICMP);
    struct timeval timeout_value = {
        .tv_sec = 1,
        .tv_usec = 0
    };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
        (void *)&g_ping_stats.specs.timeout, sizeof(g_ping_stats.specs.timeout));
    setsockopt(sockfd, IPPROTO_IP, IP_TTL,
        (void *)&g_ping_stats.specs.ttl, sizeof(g_ping_stats.specs.ttl));

    if (sockfd == -1)
        handle_error("Error in socket", 1);
    socket_address = get_sockaddr(dest_addrinfo);
    if (socket_address == NULL)
        handle_error("Error in get_sockaddr", 1);

    getnameinfo(dest_addrinfo->ai_addr, dest_addrinfo->ai_addrlen,
    g_ping_stats.specs.resolved_hostname, sizeof(g_ping_stats.specs.resolved_hostname), NULL, 0, 0);
    ping_routine(sockfd, socket_address, dest_addrinfo->ai_addrlen, g_ping_stats.specs.packet_size);
    
    freeaddrinfo(server_result);
    return 0;
}