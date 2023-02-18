#include "ft_ping.h"

static void fill_icmp_packet(char *packet_buffer, uint16_t packet_len)
{
    struct icmp     *icmp_hdr;
    struct timeval  *timestamp;

    icmp_hdr = (struct icmp *)packet_buffer;
    ft_bzero(icmp_hdr, sizeof(icmp_hdr));
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_seq = my_htons(g_ping_env.send_infos.current_seq);
    icmp_hdr->icmp_id = my_htons((uint16_t)getpid());
    if (g_ping_env.spec.timestamp)
    {
        timestamp = (struct timeval *)((void *)icmp_hdr + ICMP_MINLEN);
        *timestamp = get_timeval();
    }
    icmp_hdr->icmp_cksum = in_cksum((uint16_t *)packet_buffer, packet_len);
}

void send_icmp_packet(void)
{
    static char     packet_buffer[IP_MAXPACKET];
    int8_t          sendto_status;

    fill_icmp_packet(packet_buffer, PACKET_SIZE);
    sendto_status = sendto(g_ping_env.sockfd,
                            packet_buffer,
                            PACKET_SIZE, 0,
                            &g_ping_env.dest.sock_addr,
                            g_ping_env.dest.addr_info.ai_addrlen);
    if (sendto_status > 0)
        g_ping_env.send_infos.packet_sent++;
}