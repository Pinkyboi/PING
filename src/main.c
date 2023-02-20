#include "ft_ping.h"

t_ping_env g_ping_env = {
    .spec = {
        .interval = DEFAULT_INTERVAL,
        .packetlen = DEFAULT_PACKETLEN,
        .ttl = DEFAULT_TTL,
        .timeout = { DEFAULT_TIMEOUT_SEC, 0 },
        .holderr = true,
        .timestamp = true,
    },
    .send_infos = {
        .current_seq = 1,
        .aknowledged = false,
        .stop = false,
    }
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
    if (socketfail)
        error(2, 0, "Internal error"); 
    socketfail = setsockopt( g_ping_env.sockfd,
                             IPPROTO_IP, IP_RECVERR,
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
        print_rtt_current_stats();
}

void ping_routine()
{
    print_ping_header();
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    signal(SIGQUIT, handle_signal);
    g_ping_env.send_infos.s_time = get_timeval();
    handle_signal(SIGALRM);
    while(!g_ping_env.send_infos.stop)
    {
        if ((g_ping_env.spec.opts & OPT_NPACKET) &&
            g_ping_env.spec.npacket == g_ping_env.send_infos.packet_recv)
            break;
        if (!g_ping_env.send_infos.aknowledged)
            receive_icmp_packet();
        usleep(10);
    }
    print_ping_statistics();
};

int main(int argc, char **argv)
{
    if (getuid())
        error(2, 0, "You need to be root to run this program");
    get_ping_opt(argc, argv);
    get_dest_addr(g_ping_env.dest.name);
    resolve_ipv4_addr(g_ping_env.dest.bytes_addr);
    if (!strcmp(g_ping_env.dest.name, g_ping_env.last_resolved_addr.num_addr))
        g_ping_env.spec.opts |= OPT_NUMERIC;
    setup_socket();
    ping_routine();
}