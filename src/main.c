
#include "ping.h"

addrinfo *get_first_valid_addrinfo(addrinfo *server_result)
{

    for (addrinfo *p = server_result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
            break;
        else if (p->ai_protocol != IPPROTO_TCP && p->ai_protocol != IPPROTO_UDP)
            break;
        else if (p->ai_addrlen != sizeof(sockaddr_in) && p->ai_addrlen != sizeof(sockaddr_in6))
            break;
        else if (p->ai_socktype != SOCK_STREAM)
            break;
        else if (p->ai_addr == NULL)
            break;
        else
            return p;
    }
    return NULL;
}


void get_naddress_info(addrinfo *addrinfo, void** addr, char** ipver)
{
    if (addrinfo->ai_family == AF_INET)
    { // IPv4
        *addr = &(((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr);
        *ipver = strdup("IPv4");
    }
    else
    { // IPv6
        *addr = &(((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr);
        *ipver = strdup("IPv6");
    }
}



int main(int argc, char **argv)
{
    int con_status;
    addrinfo hints;
    addrinfo *server_result;

    memset(&hints, 0, sizeof(hints));
    hints = (addrinfo){ .ai_family = AF_UNSPEC,
                        .ai_socktype = SOCK_STREAM,
                        .ai_flags = AI_PASSIVE };

    if (argc != 2)
        exit(1);

    if (con_status == getaddrinfo(argv[1], NULL, &hints, &server_result))
        exit(1);

    char ipstr[INET6_ADDRSTRLEN];
    char *ipver;
    void *addr;

    addrinfo *p;

    p = get_valid_first_addrinfo(server_result);

    get_network_address(p, &addr, &ipver);
    inet_ntop(p->ai_family, addr, ipstr, INET6_ADDRSTRLEN);


    freeaddrinfo(server_result);
    freeaddrinfo(p);
    free(ipver);
    free(addr);
    return 0;
}