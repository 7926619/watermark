#ifndef CALC_CHECKSUM_H
#define CALC_CHECKSUM_H

#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <iostream>

struct pseudo_header{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short calc_tcpcs(u_char *buf);
unsigned short calc_ipcs(u_char *buf);

#endif // CALC_CHECKSUM_H
