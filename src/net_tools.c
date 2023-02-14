#include "ping.h"

uint16_t my_ntohs(int16_t nshort)
{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return ((((nshort) & 0xFF00) >> 8) | (((nshort) & 0x00FF) << 8));
    #else
        return nshort;
    #endif
}

uint16_t my_htons(int16_t nshort)
{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return ((((nshort) & 0x00FF) << 8) | (((nshort) & 0xFF00) >> 8));
    #else
        return nshort;
    #endif
}

uint16_t in_cksum(uint16_t *buff, ssize_t size)
{
    int count = size;
    uint32_t checksum = 0;

    while (count > 1)
    {
        checksum += *(buff++);
        count -= 2;
    }
    if (count)
        checksum += *(uint8_t *)buff;

    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum += (checksum >> 16);

    return ~checksum;
}
