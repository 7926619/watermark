#include "wm_delete.h"
#include "calc_checksum.h"

bool wm_delete(u_char *buf, int *len) {
    u_char wm_start[] = { 0x61, 0xc0, 0x01, 0xf8 };
    int index = 0;
    unsigned short result = 0;

    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));
    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
    memcpy(tcp_hdr, buf + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));

    index = find_index(buf, wm_start, len, 4);
    if(index == -1) {
        //printf("start_pos not found...\n");
        return false;
    }

    /* insert watermark */
    get_wm();
    for(int i = 0; i < 1674; i++) {
        buf[index + i] = watermark[i];
    }

    for(int i = 1674; i < 1680; i++) {
        buf[index + i] = data_end[i - 1674];
    }

    *len = 5514;
    for(int i = 1680; i < *len; i++) {
        buf[index + i] = '\x00';
    }

    // change ip->totlen
    buf[0x10] = 0x15;
    buf[0x11] = 0x7c;

    // change ip->sum
    result = calc_ipcs(buf);
    buf[0x12] = (result & 0xff00) >> 8;
    buf[0x13] = result & 0xff;

    // change tcp->sum
    result = calc_tcpcs(buf);
    buf[0x32] = (result & 0xff00) >> 8;
    buf[0x33] = result & 0xff;

    return true;
}
