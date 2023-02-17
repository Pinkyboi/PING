#include "ft_ping.h"

static void fill_icmp_packet(char *packet_buffer, uint16_t packet_len)
{
    struct icmp     *icmp_hdr;
    struct timeval  *timestamp;

    ft_bzero(packet_buffer, packet_len);
    icmp_hdr = (struct icmp *)packet_buffer;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_seq = my_htons(g_ping_env.send_infos.current_seq++);
    icmp_hdr->icmp_id = my_htons(getpid());
    if ((u_long)(packet_len - ICMP_HDR_SIZE) > sizeof(struct timeval))
    {
        timestamp = (struct timeval *)((void *)icmp_hdr + sizeof(struct icmp));
        *timestamp = get_timeval();
    }
    icmp_hdr->icmp_cksum = in_cksum((uint16_t *)packet_buffer, packet_len);
}

void send_icmp_packet(void)
{
    char            packet_buffer[PACKET_SIZE];
    int8_t          sendto_status;

    fill_icmp_packet(packet_buffer, sizeof(packet_buffer));
    sendto_status = sendto(g_ping_env.sockfd,
                            packet_buffer,
                            sizeof(packet_buffer), 0,
                            &g_ping_env.dest.sock_addr,
                            g_ping_env.dest.addr_info.ai_addrlen);
    if (sendto_status > 0)
    {
        g_ping_env.send_infos.packet_sent++;
        g_ping_env.send_infos.aknowledged = false;
    }
}