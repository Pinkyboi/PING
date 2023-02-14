
#include "ping.h"

struct timeval get_timeval()
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv;
}

float get_time_diff(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
}
