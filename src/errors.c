#include "ft_ping.h"

static void print_ip_hdr(struct ip* ip_hdr)
{
    (void) ip_hdr;
    return;
}

void print_icmp_err(int type, int code, struct ip* ip_hdr)
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
            if (ip_hdr && g_ping_env.spec.opts & OPT_VERBOSE)
                print_ip_hdr(ip_hdr);
        }
    }
    else if (type == ICMP_TIMXCEED)
    {
        if (code == ICMP_TIMXCEED_INTRANS)
            printf("Time to Live Exceeded\n");
        else if (code == ICMP_TIMXCEED_REASS)
            printf("Fragment Reassembly Time exceeded\n");
        else
        {
            printf("Time Exceeded, Bad Code %d\n", code);
            if (ip_hdr && g_ping_env.spec.opts & OPT_VERBOSE)
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
            if (ip_hdr && g_ping_env.spec.opts & OPT_VERBOSE)
                print_ip_hdr(ip_hdr);
        }
    }
    else
    {
        printf("Bad ICMP type: %d\n", type);
        if (ip_hdr && g_ping_env.spec.opts & OPT_VERBOSE)
            print_ip_hdr(ip_hdr);
    }
}

void error(uint8_t code, int err, char *err_format, ...)
{
    va_list args;

    fprintf(stderr, "%s: ", PROGNAME);
    va_start(args, err_format);
    vfprintf(stderr, err_format, args);
    if (err)
        fprintf(stderr, ": %s", strerror(err));
    va_end(args);
    fprintf(stderr, "\n");
    exit(code);
}
