#include "ft_ping.h"

void print_ping_header(void)
{
    printf("PING %s (%s): %d(%d) bytes of data\n",
        g_ping_env.dest.name,
        g_ping_env.last_resolved_addr.num_addr,
        g_ping_env.spec.packetlen,
        g_ping_env.spec.packetlen + ICMP_MINLEN);
}

static void packet_statistics(void)
{
    int   time_passed;

    time_passed = usec_time_diff(g_ping_env.send_infos.s_time, get_timeval());
    printf( "%d packets transmitted, %d packets received, ",
                g_ping_env.send_infos.packet_sent,
                g_ping_env.send_infos.packet_recv);
    if (g_ping_env.send_infos.error_count)
        printf("+%d errors, ", g_ping_env.send_infos.error_count);
    printf("%.1f%% packet loss, time %dms\n",
                LOSS_PERCENT( g_ping_env.send_infos.packet_recv,
                              g_ping_env.send_infos.packet_sent ),
                time_passed );
}

static void print_rtt_final_statistics(void)
{
    float   avg_rtt;
    float   mdev_rtt;

    avg_rtt = g_ping_env.rtt.rtt_sum / g_ping_env.rtt.rtt_count;
    mdev_rtt = get_mdev_rtt(g_ping_env.rtt.rtt_list, avg_rtt);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
            g_ping_env.rtt.rtt_min,
            avg_rtt,
            g_ping_env.rtt.rtt_max,
            mdev_rtt);
}

void print_ping_statistics(void)
{
    printf("\n--- %s ping statistics ---\n", g_ping_env.dest.name);
    packet_statistics();
    if (g_ping_env.rtt.rtt_list)
        print_rtt_final_statistics();
}

void print_rtt_current_stats(void)
{
    float   avg_rtt;

    avg_rtt = g_ping_env.rtt.rtt_sum / g_ping_env.rtt.rtt_count;
    printf("%d/%d packets, %d%% loss, min/avg/ewma/max = %.3f/%.3f/%.3f/%.3f ms\n",
            g_ping_env.send_infos.packet_recv,
            g_ping_env.send_infos.packet_sent,
            (int)LOSS_PERCENT(g_ping_env.send_infos.packet_recv,
                            g_ping_env.send_infos.packet_sent ),
            g_ping_env.rtt.rtt_min,
            avg_rtt,
            g_ping_env.rtt.rtt_ewma,
            g_ping_env.rtt.rtt_max);
}

void print_err_response(uint16_t sequence, uint8_t type, uint8_t code, struct ip* ip_hdr)
{
    if (g_ping_env.spec.opts & OPT_NUMERIC)
    {
        printf( "From %s icmp_seq=%d ",
                g_ping_env.last_resolved_addr.num_addr,
                sequence);
    }
    else
    {
        printf( "From %s (%s) icmp_seq=%d ",
                g_ping_env.last_resolved_addr.full_addr,
                g_ping_env.last_resolved_addr.num_addr,
                sequence );
    }
    print_icmp_err(type, code, ip_hdr);
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
