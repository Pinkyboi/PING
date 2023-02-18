
#include "ft_ping.h"


static int64_t strtol_or_err(char *arg, char *err_msg, long min_value, long max_value)
{
    long num_arg;
    char *end_ptr = NULL;

    errno = 0;
    if (arg == NULL || *arg == '\0')
        error(2, 0, err_msg);
    num_arg = strtol(arg, &end_ptr, 10);
    if (errno || arg == end_ptr || (end_ptr && *end_ptr))
        error(2, errno, err_msg, arg);
    if (num_arg < min_value || num_arg > max_value)
        error(2, 0, ERR_RANGE_ARG_MSG, arg, min_value, max_value);
    return (num_arg);
}

static void pingv4_usage(void)
{
    printf("\nUsage\n  ping [options] <destination>\n");
    printf("\nOptions:\n");
    printf("  <destination>      dns name or ip address\n");
    printf("  -h                 print help and exit\n");
    printf("  -v                 verbose output\n");
    printf("  -n                 no dns name resolution\n");
    printf("  -i <interval>      seconds between sending each packet\n");
    printf("  -s <size>          use <size> as number of data bytes to be sent\n");
    printf("  -t <ttl>           define time to live\n");
    printf("  -W <timeout>       time to wait for response\n");
    printf("  -c <npacket>         stop after sending <npacket> ECHO_REQUEST packets\n");
    exit(2);
}

void get_ping_opt(int argc, char **argv)
{
    char    opt;
    float   secs;
    int64_t datalen;

    while((opt = getopt(argc, argv, "hvni:s:t:W:c:")) != EOF)
    {
        switch (opt)
        {
            case 'v':
                g_ping_env.spec.opts |= OPT_VERBOSE;
                break;
            case 'n':
                g_ping_env.spec.opts |= OPT_NUMERIC;
                break;
            case 'i':
                secs = atoi(optarg);
                if (secs <= 0.0 || secs > (double)INT32_MAX / 1000.0)
                    error(2, 0, "Bad timing interval: %s", optarg);
                g_ping_env.spec.interval = secs;
                break;
            case 's':
			    datalen = atoi(optarg);
			    if (datalen < 0)
			    	error(2, 0, ERR_N_PACKET_SIZE, datalen);
			    if (datalen > ICMP_MAXDATA)
                    error(2, 0, ERR_L_PACKET_SIZE, datalen);
                if ((size_t)datalen < sizeof(struct timeval))
                    g_ping_env.spec.timestamp = false;
                g_ping_env.spec.packetlen = datalen;
                break;
            case 't':
                g_ping_env.spec.ttl = strtol_or_err(optarg, ERR_INVALID_ARG, 1, MAXTTL);;
                break;
            case 'W':
                secs = atof(optarg);
                if (secs <= 0.0 || secs > (double)INT32_MAX / 1000.0)
                    error(2, 0, "Bad linger time: %s", optarg);
                g_ping_env.spec.timeout = secs_to_timeval(secs);
                break;
            case 'c':
                g_ping_env.spec.opts |= OPT_NPACKET;
                g_ping_env.spec.npacket = strtol_or_err(optarg, ERR_INVALID_ARG, 1, INT64_MAX);
                break;
            default:
                    pingv4_usage();
                break;
        }
    }
	argc -= optind;
	argv += optind;
    if (!argc)
        error(2, 0,  "usage error: %s", "Destination required");
    g_ping_env.dest.name = argv[argc - 1];
}