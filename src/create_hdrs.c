
#include "ping.h"

void create_icmp_header(char *packet_buffer, int packet_len, int seq)
{
    struct icmp *icmp_header;

    ft_bzero(packet_buffer, packet_len + ICMP_HDR_LEN);
    icmp_header = (struct icmp *)packet_buffer;
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_seq = my_htons(seq);
    icmp_header->icmp_id = my_htons(getpid());
    icmp_header->icmp_cksum = in_cksum((uint16_t *)packet_buffer, packet_len + ICMP_HDR_LEN);
}

t_msg_data create_message_header(void* message_buffer, int message_len,
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
