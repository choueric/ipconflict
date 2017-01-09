#ifndef _ARP_SEND_H
#define _ARP_SEND_H

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <stdint.h>

struct arp_packet {
    struct ethhdr eth_header;   // ethernet packet header,  size: 14
    struct arphdr arp_header;   // arp packet header, size: 8
    uint8_t arp_sha[ETH_ALEN];     // arp packet content, size: 20
    uint8_t arp_spa[4];
    uint8_t arp_tha[ETH_ALEN];
    uint8_t arp_tpa[4];
};

int arp_send_probe(char *ifname, uint32_t ip, uint8_t *mac);

int arp_send_defend(char *ifname, uint32_t ip, uint8_t *mac);

int arp_send_annce(char *ifname, uint32_t ip, uint8_t *mac);


#endif

