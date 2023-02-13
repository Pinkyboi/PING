#include "ping.h"

t_ping_stats    g_ping_stats;

uint16_t my_ntohs(int16_t nshort)
{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return ((((nshort) & 0xFF00) >> 8) | (((nshort) & 0x00FF) << 8));
    #else
        return nshort;
    #endif
}

uint16_t my_htons(int16_t nshort)
{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return ((((nshort) & 0x00FF) << 8) | (((nshort) & 0xFF00) >> 8));
    #else
        return nshort;
    #endif
}

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
    icmp_header->icmp_id = (uint16_t)getpid();
    icmp_header->icmp_cksum = checksum((uint16_t *)packet_buffer, packet_len);
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
        variance += pow_2(p->rtt - average_rtt);
        rtt_count++;
    }
    return newtonian_sqrt(variance / rtt_count, .0001);
}


void print_packet_recipe(struct ip* ip_header, struct icmp *icmp_header, float time_diff)
{
    if (!(g_ping_stats.specs.options & N_OPTION ) && 
        strcmp(g_ping_stats.specs.resolved_hostname_ip, g_ping_stats.specs.unresolved_hostname))
    {
        printf("%d bytes from %s", my_ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2),
            g_ping_stats.specs.resolved_hostname);
        printf(" (%s)", g_ping_stats.specs.resolved_hostname_ip);
    }
    else
        printf("%d bytes from %s", my_ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2),
            g_ping_stats.specs.resolved_hostname_ip);
    printf(" icmp=%d ttl=%d time=%.3f ms\n", icmp_header->icmp_seq, ip_header->ip_ttl,time_diff);
}

void print_ip_hdr(struct ip* ip_hdr)
{
    return;
}

void icmphdr_errors(int type, int code, struct ip* ip_hdr)
{

    if (type == ICMP_ECHOREPLY)
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
            if (ip_hdr && g_ping_stats.specs.options & V_OPTION)
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
            if (ip_hdr && g_ping_stats.specs.options & V_OPTION)
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
            if (ip_hdr && g_ping_stats.specs.options & V_OPTION)
                print_ip_hdr(ip_hdr);
        }
    }
    else
    {
        printf("Bad ICMP type: %d\n", type);
        if (ip_hdr && g_ping_stats.specs.options & V_OPTION)
            print_ip_hdr(ip_hdr);
    }
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
    if (icmp_hdr->icmp_id != (uint16_t)getpid())
        return NULL;
    packet_node = get_packet_node(packet_list, icmp_hdr->icmp_seq);
    if (!packet_node->rtt)
    {
        packet_node->recv_time = recv_time;
        print_packet_recipe(ip_hdr, icmp_hdr, get_time_diff(packet_node->send_time,
            packet_node->recv_time));
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

float newtonian_sqrt(float x, float precision)
{
    float   guess;
    float   guess_squared;
    float   new_guess;

    guess = x / 2;
    guess_squared = guess * guess;
    while (guess_squared - x > precision || x - guess_squared > precision)
    {
        new_guess = (guess + x / guess) / 2;
        guess = new_guess;
        guess_squared = guess * guess;
    }
    return guess;
}

float pow_2(float x)
{
    return x * x;
}

t_msg_data create_message_header(void* message_buffer, int message_len,
    void *control_buffer, int control_len)
{
    t_msg_data msg;

    msg.msg_iov.iov_base = message_buffer;
    msg.msg_hdr.msg_iov = &msg.msg_iov;
    msg.msg_iov.iov_len = message_len;
    msg.msg_hdr.msg_iovlen = 1;
    msg.msg_hdr.msg_control = control_buffer;
    msg.msg_hdr.msg_controllen = control_len;
    return msg;
}


void check_err_msg(int sockfd, int packet_len)
{
    char                        recv_buffer[ICMP_HDR_LEN + IP_HDR_LEN + packet_len];
    char                        control_buffer[1024];
    t_msg_data                  err_msg;
    int                         control_bytes;
    t_cmsg_info                 cmsg_info;

    err_msg = create_message_header(recv_buffer, sizeof(recv_buffer),
        control_buffer, sizeof(control_buffer));
    control_bytes = recvmsg(sockfd, &err_msg.msg_hdr, MSG_DONTWAIT | MSG_ERRQUEUE);
    if (control_bytes <= 0)
        return ;
    cmsg_info.error_ptr = NULL;
    cmsg_info.cmsg = CMSG_FIRSTHDR(&err_msg.msg_hdr);
    while (cmsg_info.cmsg)
    {
        if (cmsg_info.cmsg->cmsg_level == SOL_IP && cmsg_info.cmsg->cmsg_type == IP_RECVERR)
            cmsg_info.error_ptr = (struct sock_extended_err *)CMSG_DATA(cmsg_info.cmsg);
        cmsg_info.cmsg = CMSG_NXTHDR(&err_msg.msg_hdr, cmsg_info.cmsg);
    }
    if (cmsg_info.error_ptr)
    {
        printf("%d bytes From %s: ", control_bytes,
            inet_ntoa(((struct sockaddr_in *)SO_EE_OFFENDER(cmsg_info.error_ptr))->sin_addr));
        icmphdr_errors(cmsg_info.error_ptr->ee_type, cmsg_info.error_ptr->ee_code, NULL);
    }
}


void receive_icmp_packet(int sockfd, int packet_len)
{
    char                    recv_buffer[ICMP_HDR_LEN + IP_HDR_LEN + packet_len];
    char                    control_buffer[C_DATA_LEN];
    t_msg_data              re_msg;
    t_packet_node           *packet_node;
    int                     message_bytes;

    re_msg = create_message_header(recv_buffer, sizeof(recv_buffer), 
            control_buffer, sizeof(control_buffer));
    message_bytes = recvmsg(sockfd, &re_msg.msg_hdr, MSG_WAITALL);
    if (message_bytes < 0 && errno == EWOULDBLOCK)
        printf("Request timeout for icmp_seq %d\n", g_ping_stats.packet_sent_nbr - 1);     
    if (message_bytes > 0)
    {
        packet_node = read_packet_message(recv_buffer, packet_len,
            g_ping_stats.rtt_info.packet_list, get_timeval());
        if (packet_node != NULL)
        {
            update_rtt_info(&g_ping_stats.rtt_info, packet_node->send_time,
                packet_node->recv_time);
            g_ping_stats.packet_recv_nbr++;
        }
    }
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
        add_packet_node(&g_ping_stats.rtt_info.packet_list,
            send_time, (struct timeval){0, 0}, seq);
        g_ping_stats.packet_sent_nbr++;
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
    printf("\n--- %s ping statistics ---\n", g_ping_stats.specs.unresolved_hostname);
    print_packet_statistics(g_ping_stats.packet_sent_nbr, g_ping_stats.packet_recv_nbr);
    if (g_ping_stats.packet_recv_nbr)
        print_rtt_infos(signnum);
    exit(0);
}


void print_ping_header(void)
{
    printf("PING %s (%s): %d data bytes\n",
        g_ping_stats.specs.unresolved_hostname,
        g_ping_stats.specs.resolved_hostname_ip,
        g_ping_stats.specs.packet_size);
}

void ping_routine(int sockfd, struct sockaddr *dest_addr, int dest_addr_len, int packet_len)
{
    int             seq;

    seq = 0;
    print_ping_header();
    signal(SIGALRM, unlock_sending);
    signal(SIGINT, print_ping_statistics);
    while (true)
    {
        if (g_ping_stats.sending_status)
        {
            send_icmp_packet(sockfd, dest_addr, dest_addr_len, packet_len, seq);
            g_ping_stats.sending_status = false;
            seq++;
            receive_icmp_packet(sockfd, packet_len);
            alarm(g_ping_stats.specs.interval);
        }
        check_err_msg(sockfd, packet_len);
        if (g_ping_stats.specs.options & C_OPTION && seq == g_ping_stats.specs.max_packet)
            print_ping_statistics(0);
        usleep(100);
    }
}

struct addrinfo* get_host_addrinfo(char *host_name)
{
    struct addrinfo hints;
    struct addrinfo *server_result;

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

void get_ping_options(char **prog_arg)
{
    int i = 0;
    int step = 1;
    char *argument;

    while(prog_arg[i])
    {
        step = 1;
        if (*prog_arg[i] == '-')
        {
            if (!strcmp(prog_arg[i], "-v"))
                g_ping_stats.specs.options |= V_OPTION;
            else if (!strcmp(prog_arg[i], "-h"))
                pingv4_usage();
            else if (!strcmp(prog_arg[i], "-n"))
                g_ping_stats.specs.options |= N_OPTION;
            else
            {
                if (strlen(prog_arg[i]) != 2)
                    argument = prog_arg[i] + 2;
                else
                {
                    argument = prog_arg[i + 1];
                    step = 2;
                }
                if (!strncmp(prog_arg[i], "-c", 2))
                {
                    g_ping_stats.specs.options |= C_OPTION;
                    g_ping_stats.specs.max_packet = get_option_num_arg(argument, MAX_PACKET_COUNT, "-c");
                }
                else if (!strncmp(prog_arg[i], "-i", 2))
                    g_ping_stats.specs.interval = get_option_num_arg(argument, MAX_INTERVAL, "-i");
                else if (!strncmp(prog_arg[i], "-s", 2))
                    g_ping_stats.specs.packet_size = get_option_num_arg(argument, MAX_PACKET_SIZE, "-s");
                else if (!strncmp(prog_arg[i], "-W", 2))
                    g_ping_stats.specs.timeout.tv_sec = get_option_num_arg(argument, MAX_TIMEOUT, "-W");
                else if (!strncmp(prog_arg[i], "-t", 2))
                    g_ping_stats.specs.ttl = get_option_num_arg(argument, MAX_TTL, "-t");
                else
                {
                    printf("ping: unknown option -- %s\n", prog_arg[i]);
                    pingv4_usage();
                }
            }
        }
        else if (g_ping_stats.specs.unresolved_hostname == NULL)
            g_ping_stats.specs.unresolved_hostname = prog_arg[i];
        else
            pingv4_usage();
        i += step;
    }
}


void init_ping(void)
{
    g_ping_stats.sending_status = true;
    g_ping_stats.start_time = get_timeval();
    g_ping_stats.specs.timeout = (struct timeval){.tv_sec = DEFAULT_TIMEOUT_SEC, 0};
    g_ping_stats.specs.unresolved_hostname = NULL;
    g_ping_stats.specs.packet_size = DEFAUL_TPACKET_SIZE;
    g_ping_stats.specs.interval = DEFAULT_INTERVAL;
    g_ping_stats.specs.ttl = DEFAULT_TTL;
    g_ping_stats.specs.hold_err = true;
}

void set_socket_opt(int sockfd)
{
    bool socketfail;

    socketfail = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
        (void *)&g_ping_stats.specs.timeout, sizeof(g_ping_stats.specs.timeout));
    if (socketfail)
        handle_error("ping: Internal error", 1);
    socketfail = setsockopt(sockfd, SOL_IP, IP_RECVERR,
        (char *)&g_ping_stats.specs.hold_err, sizeof(g_ping_stats.specs.hold_err));
    if (socketfail)
        handle_error("ping: Internal error", 1);
    socketfail = setsockopt(sockfd, IPPROTO_IP, IP_TTL,
        (void *)&g_ping_stats.specs.ttl, sizeof(g_ping_stats.specs.ttl));
    if (socketfail)
        handle_error("ping: Internal error", 1);
}

void start_connection(struct addrinfo *dest_addrinfo)
{
    int                 sockfd;
    struct sockaddr     *socket_address;
    struct sockaddr_in  *socket_address_in;

    sockfd = socket(dest_addrinfo->ai_family, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
        handle_error("ping: Error establishing connection", 1);
    socket_address = dest_addrinfo->ai_addr;
    socket_address_in = (struct sockaddr_in *)socket_address;
    if (socket_address == NULL)
        handle_error("ping: Error establishing connection", 1);
    set_socket_opt(sockfd);
    inet_ntop(dest_addrinfo->ai_family, &socket_address_in->sin_addr, g_ping_stats.specs.resolved_hostname_ip,
        sizeof(g_ping_stats.specs.resolved_hostname_ip));
    getnameinfo(dest_addrinfo->ai_addr, dest_addrinfo->ai_addrlen,
        g_ping_stats.specs.resolved_hostname, sizeof(g_ping_stats.specs.resolved_hostname), NULL, 0, 0);
    ping_routine(sockfd, socket_address, dest_addrinfo->ai_addrlen, g_ping_stats.specs.packet_size);
    close(sockfd);
}

int main(int argc, char **argv)
{
    struct addrinfo *server_result;
    struct addrinfo *dest_addrinfo;

    if (argc == 1)
        pingv4_usage();
    init_ping();
    get_ping_options(&argv[1]);
    server_result = get_host_addrinfo(g_ping_stats.specs.unresolved_hostname);
    dest_addrinfo = get_first_valid_addrinfo(server_result);
    if (dest_addrinfo == NULL)
    {
        printf("ping: cannot resolve %s: %s",
            g_ping_stats.specs.unresolved_hostname, gai_strerror(errno));
        exit(1);
    }
    start_connection(dest_addrinfo);
    freeaddrinfo(server_result);
    return 0;
}
