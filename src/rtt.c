#include "ft_ping.h"

float get_mdev_rtt(t_list *rtt_list, float avg_rtt)
{
    float   mdev_rtt;
    float   rtt;
    t_list  *tmp;

    mdev_rtt = 0;
    tmp = rtt_list;
    while (tmp)
    {
        rtt = *(float *)tmp->content;
        mdev_rtt += (rtt - avg_rtt) * (rtt - avg_rtt);
        tmp = tmp->next;
    }
    mdev_rtt /= g_ping_env.rtt.rtt_count;
    mdev_rtt = sqrt(mdev_rtt);
    return mdev_rtt;
}

void update_rtt(float rtt)
{
    if (rtt)
    {
        g_ping_env.rtt.rtt_sum += rtt;
        if (g_ping_env.rtt.rtt_min == 0 || g_ping_env.rtt.rtt_min > rtt)
            g_ping_env.rtt.rtt_min = rtt;
        if (g_ping_env.rtt.rtt_min == 0 || g_ping_env.rtt.rtt_max < rtt)
            g_ping_env.rtt.rtt_max = rtt;
        ft_lstadd(&g_ping_env.rtt.rtt_list, ft_lstnew(&rtt, sizeof(float)));
        g_ping_env.rtt.rtt_count++;
        g_ping_env.rtt.rtt_ewma = RTT_EWMA(rtt);
    }
}

float add_packet_rtt(void *icmp_packet)
{
    struct timeval  *time;
    float           time_diff;

    time_diff = 0;
    if (g_ping_env.spec.timestamp)
    {
        time = (struct timeval *)((void *)icmp_packet + ICMP_MINLEN);
        time_diff = usec_time_diff(*time, get_timeval());
        update_rtt(time_diff);
    }
    return time_diff;
}
