#include "calc_checksum.h"

unsigned short calc_tcpcs(u_char *buf) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(buf[0x2e] * 4));
    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
    memcpy(tcp_hdr, buf + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, buf[0x2e] * 4);
    unsigned char *data = buf + sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;

    struct pseudo_header *psh;
    u_char *tmp;
    unsigned long sum_p = 0, sum_t = 0, sum = 0;
    unsigned int data_length, tcp_length;
    unsigned short result = 0;
    int cnt;

    psh = (pseudo_header*) malloc(sizeof(pseudo_header));
    psh->source_address = inet_addr(inet_ntoa(ip_hdr->ip_src));
    psh->dest_address = inet_addr(inet_ntoa(ip_hdr->ip_dst));

    psh->placeholder = 0;
    psh->protocol = 6;
    data_length = ntohs(ip_hdr->ip_len) - (tcp_hdr->th_off * 4) - (ip_hdr->ip_hl * 4);
    psh->tcp_length = htons(tcp_hdr->th_off * 4 + data_length);

    tmp = (u_char *)psh;
    /* sum pseudo_header */
    for(int i = 0; i < sizeof(pseudo_header); i += 2) {
        sum_p += (tmp[i] << 8) + tmp[i+1];
        while(sum_p >= 0x10000) {
            sum_p -= 0x10000;
            sum_p += 1;
        }
    }

    /* sum tcp stream */
    tcp_hdr->th_sum = 0;
    tmp = (u_char *)tcp_hdr;
    tcp_length = tcp_hdr->th_off * 4 + data_length;
    for(int i = 0; i < tcp_hdr->th_off * 4; i += 2) {
        sum_t += (tmp[i] << 8) + tmp[i+1];
        while(sum_t >= 0x10000) {
            sum_t -= 0x10000;
            sum_t += 1;
        }
    }

    cnt = data_length;
    if(data_length % 2 == 1) {
        cnt = data_length - 1;
    }

    for(int i = 0; i < cnt; i += 2) {
        sum_t += (data[i] << 8) + data[i+1];
        while(sum_t >= 0x10000) {
            sum_t -= 0x10000;
            sum_t += 1;
        }
    }
    if(data_length % 2 == 1) {
        sum_t += data[data_length - 1] << 8;
    }
    if(sum_t >= 0x10000) {
        sum_t -= 0x10000;
        sum_t += 1;
    }

    sum = sum_p + sum_t;
    if(sum >= 0x10000) {
        sum -= 0x10000;
        sum += 1;
    }
    result = (unsigned short) ~sum;

    return result;
}

unsigned short calc_ipcs(u_char *buf) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));

    u_char *tmp;
    unsigned long sum = 0;
    unsigned short result = 0;

    ip_hdr->ip_sum = 0;
    tmp = (u_char *)ip_hdr;
    for(int i = 0; i < ip_hdr->ip_hl * 4; i += 2) {
        sum += (tmp[i] << 8) + tmp[i+1];
        while(sum >= 0x10000) {
            sum -= 0x10000;
            sum += 1;
        }
    }

    result = (unsigned short) ~sum;

    return result;
}
