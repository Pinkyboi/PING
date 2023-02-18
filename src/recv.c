#include "ft_ping.h"

static t_msg_data create_message_header(void* message_buffer, int message_len,
                                    void *control_buffer, int control_len)
{
    t_msg_data msg;

    msg = (t_msg_data){0};
    ft_bzero(message_buffer, message_len);
    ft_bzero(control_buffer, control_len);
    msg.msg_iov.iov_base = message_buffer;
    msg.msg_iov.iov_len = message_len;
    msg.msg_hdr.msg_control = control_buffer;
    msg.msg_hdr.msg_controllen = control_len;
    msg.msg_hdr.msg_iov = &msg.msg_iov;
    msg.msg_hdr.msg_iovlen = 1;
    return msg;
}

static void aknowledge(uint16_t seq)
{
    if (seq <= g_ping_env.send_infos.current_seq)
        g_ping_env.send_infos.aknowledged = true;
}

static const char* get_corruption_msg(struct icmp *icmp_hdr, uint32_t icmp_len)
{
    if (icmp_len < ICMP_MINLEN)
        return "(size too small)";
    if (in_cksum((void *)icmp_hdr, icmp_len))
        return "(BAD CHECKSUM)";
    if (icmp_len < ICMP_MINLEN + g_ping_env.spec.packetlen)
        return "(truncated)";
    if (icmp_hdr->icmp_seq < g_ping_env.send_infos.current_seq - 1)
        return "(DUP!)";
    return NULL;
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


static void parse_icmp_packet(char *message_buffer, uint32_t datalen)
{
    struct ip       *ip_hdr;
    struct icmp     *icmp_hdr;
    const char      *err_msg;
    float           time_diff;
    uint32_t        icmp_len;

    ip_hdr = (struct ip *)message_buffer;
    icmp_hdr = (struct icmp *)(message_buffer + (ip_hdr->ip_hl << 2));
    icmp_len = datalen - (ip_hdr->ip_hl << 2);
    err_msg = get_corruption_msg(icmp_hdr, icmp_len);
    if (my_ntohs(icmp_hdr->icmp_id) == (uint16_t)getpid() &&
            ip_hdr->ip_p == IPPROTO_ICMP)
    {
        aknowledge(my_ntohs(icmp_hdr->icmp_seq));
        resolve_ipv4_addr(ip_hdr->ip_src);
        if (icmp_hdr->icmp_type == ICMP_ECHOREPLY &&
            icmp_hdr->icmp_code == 0)
        {
            time_diff = add_packet_rtt(icmp_hdr);
            print_response_packet(  icmp_len,
                                    my_ntohs(icmp_hdr->icmp_seq),
                                    ip_hdr->ip_ttl,
                                    time_diff,
                                    err_msg );
        }
        else
        {
            g_ping_env.send_infos.error_count++;
            if (g_ping_env.spec.opts & OPT_VERBOSE)
            {
                print_err_response( icmp_hdr->icmp_seq,
                                    icmp_hdr->icmp_type,
                                    icmp_hdr->icmp_code,
                                    ip_hdr );
            }
        }
    }
}

void parse_err_packet(struct sock_extended_err *err, uint16_t sequence)
{
    struct in_addr              src_addr;

    aknowledge(sequence);
    src_addr = ((struct sockaddr_in *)SO_EE_OFFENDER(err))->sin_addr;
    resolve_ipv4_addr(src_addr);
    print_err_response(sequence, err->ee_type, err->ee_code, NULL);
    g_ping_env.send_infos.error_count++;
}

void read_err_msg(void)
{
    static char                 control_buffer[C_MAXPACKET];
    struct icmp                 icmp_hdr;
    t_msg_data                  err_msg;
    t_cmsg_info                 cmsg_info;

    err_msg = create_message_header(&icmp_hdr, sizeof(icmp_hdr),
        control_buffer, sizeof(control_buffer));
    if (recvmsg(g_ping_env.sockfd, &err_msg.msg_hdr, MSG_ERRQUEUE) > 0)
    {
        cmsg_info = (t_cmsg_info){.cmsg = CMSG_FIRSTHDR(&err_msg.msg_hdr)};
        while (cmsg_info.cmsg)
        {
            if (cmsg_info.cmsg->cmsg_level == SOL_IP &&
                    cmsg_info.cmsg->cmsg_type == IP_RECVERR)
                cmsg_info.error_ptr = (struct sock_extended_err *)CMSG_DATA(cmsg_info.cmsg);
            cmsg_info.cmsg = CMSG_NXTHDR(&err_msg.msg_hdr, cmsg_info.cmsg);
        }
        if (cmsg_info.error_ptr)
            parse_err_packet(cmsg_info.error_ptr, my_htons(icmp_hdr.icmp_seq));
    }
}

void receive_icmp_packet(void)
{
    static char             recv_buffer[IP_MAXPACKET];
    t_msg_data              re_msg;
    int                     message_bytes;

    re_msg = create_message_header( recv_buffer,
                                    sizeof(recv_buffer),
                                    NULL,
                                    0 );
    message_bytes = recvmsg(g_ping_env.sockfd, &re_msg.msg_hdr, 0);
    if (message_bytes > 0)
        parse_icmp_packet(recv_buffer, message_bytes);
    else if (message_bytes < 0)
        read_err_msg();
    if (message_bytes)
        g_ping_env.send_infos.packet_recv++;
}
