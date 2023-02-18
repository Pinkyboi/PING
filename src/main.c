
#include "ft_ping.h"

t_ping_env g_ping_env = {
    .spec = {
        .interval = DEFAULT_INTERVAL,
        .packetlen = DEFAULT_PACKETLEN,
        .ttl = DEFAULT_TTL,
        .timeout = { DEFAULT_TIMEOUT_SEC, 0 },
        .holderr = true
    },
    .send_infos = {
        .current_seq = 1,
        .aknowledged = false,
        .stop = false
    },
};

void setup_socket(void)
{
    bool socketfail;

    g_ping_env.sockfd = socket( g_ping_env.dest.addr_info.ai_family,
                                SOCK_RAW,
                                IPPROTO_ICMP );
    if (g_ping_env.sockfd < 0)
        error(2, errno, "%s", "socket error");
    socketfail = setsockopt( g_ping_env.sockfd,
                            SOL_SOCKET, SO_RCVTIMEO,
                            (void *)&g_ping_env.spec.timeout,
                            sizeof(g_ping_env.spec.timeout) );
    socketfail = setsockopt( g_ping_env.sockfd,
                             SOL_IP, IP_RECVERR,
                             (char *)&g_ping_env.spec.holderr,
                             sizeof(g_ping_env.spec.holderr) );
    if (socketfail)
        error(2, 0, "Internal error");
    socketfail = setsockopt( g_ping_env.sockfd,
                            IPPROTO_IP, IP_TTL,
                            (void *)&g_ping_env.spec.ttl,
                            sizeof(g_ping_env.spec.ttl) );
    if (socketfail)
        error(2, errno, "Internal error");
}

void print_ping_header(void)
{
    printf("PING %s (%s): %d(%d) bytes of data\n",
        g_ping_env.dest.name,
        g_ping_env.last_resolved_addr.num_addr,
        g_ping_env.spec.packetlen,
        g_ping_env.spec.packetlen + ICMP_MINLEN);
}

void print_response_packet(int datalen, uint16_t sequence, int ttl, int rtt, const char *err)
{
    if (g_ping_env.spec.opts & OPT_NUMERIC)
    {
        printf( "%d bytes from %s icmp_seq=%d ttl=%d",
                datalen,
                g_ping_env.last_resolved_addr.num_addr,
                sequence,
                ttl );
    }
    else
    {
        printf( "%d bytes from %s (%s) icmp_seq=%d ttl=%d",
                datalen,
                g_ping_env.last_resolved_addr.full_addr,
                g_ping_env.last_resolved_addr.num_addr,
                sequence,
                ttl );
    }
    if (rtt)
        printf(" time=%dms", rtt);
    if (err)
        printf(" %s", err);
    printf("\n");
}

void packet_statistics(void)
{
    int   time_passed;

    time_passed = usec_time_diff(g_ping_env.rtt.s_time, get_timeval());
    printf( "%d packets transmitted, %d packets received, %.1f%% packet loss, time %dms\n",
                g_ping_env.send_infos.packet_sent,
                g_ping_env.send_infos.packet_recv,
                LOSS_PERCENT(   g_ping_env.send_infos.packet_recv,
                                g_ping_env.send_infos.packet_sent ),
                time_passed );
}

void ping_statistics(void)
{
    printf("\n--- %s ping statistics ---\n", g_ping_env.dest.name);
    packet_statistics();
    if (g_ping_env.rtt.rtt_list)
        rtt_statistics();
}

void handle_signal(int sig)
{
    if (sig == SIGINT)
        g_ping_env.send_infos.stop = true;
    if (sig == SIGALRM)
    {
        send_icmp_packet();
        alarm(g_ping_env.spec.interval);
        g_ping_env.send_infos.aknowledged = false;
    }
    if (sig == SIGQUIT)
        packet_statistics();
}

void ping_routine()
{
    g_ping_env.rtt.s_time = get_timeval();
    print_ping_header();
    handle_signal(SIGALRM);
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    signal(SIGQUIT, handle_signal);
    while(!g_ping_env.send_infos.stop)
    {
        if ((g_ping_env.spec.opts & OPT_NPACKET) &&
            g_ping_env.spec.npacket == g_ping_env.send_infos.packet_recv)
            break;
        if (!g_ping_env.send_infos.aknowledged)
            receive_icmp_packet();
        usleep(10);
    }
    ping_statistics();
};

int main(int argc, char **argv)
{
    get_ping_opt(argc, argv);
    get_dest_addr(g_ping_env.dest.name);
    resolve_ipv4_addr(g_ping_env.dest.bytes_addr);
    if (!strcmp(g_ping_env.dest.name, g_ping_env.last_resolved_addr.num_addr))
        g_ping_env.spec.opts |= OPT_NUMERIC;
    setup_socket();
    ping_routine();
}