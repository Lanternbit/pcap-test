#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac_addr(bool l, struct libnet_ethernet_hdr* eth_hdr) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", l == 0 ? eth_hdr->ether_shost[i]:eth_hdr->ether_dhost[i]);
        if (i < 5) printf(":");
    }

    printf("%s", l == 0 ? " -> ":", ");
}

void print_ip_and_port(bool l, struct libnet_ipv4_hdr *ip_hdr, struct libnet_tcp_hdr *tcp_hdr) {
    uint32_t ip_addr;

    if (l == 0) ip_addr = ip_hdr->ip_src.s_addr;
    else ip_addr = ip_hdr->ip_dst.s_addr;

    for (int i = 0; i < 4; i++) {
        printf("%d", ip_addr & 0xFF);
        if (i < 3) {
            printf(".");
            ip_addr /= 256;
        }
    }

    printf(":%d", l == 0 ? htons(tcp_hdr->th_sport):htons(tcp_hdr->th_dport));
    printf("%s", l == 0 ? " -> ":"\n");
}

void print_payload(const u_char *payload) {
    for (int i = 0; i < 10; i++) {
        printf("%02x", payload[i]);

        if (i < 9) printf("|");
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(*eth_hdr) + sizeof(*ip_hdr));

        print_mac_addr(0, eth_hdr);
        print_mac_addr(1, eth_hdr);
        print_ip_and_port(0, ip_hdr, tcp_hdr);
        print_ip_and_port(1, ip_hdr, tcp_hdr);

        int hdr_size = sizeof(*eth_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
        const u_char *payload = packet + hdr_size;

        if ((int)header->caplen >= 64 && (int)header->caplen != hdr_size) print_payload(payload);
        else printf("-");

        printf("\n==================================================================================\n");
    }

    pcap_close(pcap);
}
