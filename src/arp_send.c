#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <string.h>

#include "arp_send.h"
#include "arp_listen.h"
#include "util.h"

static int get_iface_index(int fd, char *ifname)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        err("ioctl get iface index failed: %m\n");
        return -1;
    }
    return ifr.ifr_ifindex;
}

/*
 * when @shw, @dhw is NULL, set 0.0.0.0.0
 * @return: < 0, failed.
 */
static int send_arp(char *ifname, uint32_t sip, uint8_t *shw,
		uint32_t dip, uint8_t *dhw, int opcode)
{
    int i;
    int ret = 0;
    int skfd = 0;
    struct arp_packet packet;
    struct arp_packet *p = &packet;
	struct sockaddr_ll sa;

    skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (skfd < 0) {
        err("socket failed: %m\n");
        return skfd;
    }

    i = 1;
    setsockopt(skfd, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i));

    memset(p, 0, sizeof(struct arp_packet));
    /* ether header */
    memset(p->eth_header.h_dest, 0xff, ETH_ALEN);
    memcpy(p->eth_header.h_source, shw, ETH_ALEN);
    p->eth_header.h_proto = htons(ETH_P_ARP);

    /* arp header */
    p->arp_header.ar_hrd = htons(ARPHRD_ETHER);
    p->arp_header.ar_pro = htons(ETH_P_IP);
    p->arp_header.ar_hln = 6;
    p->arp_header.ar_pln = 4;
    p->arp_header.ar_op = htons(opcode);

    /* arp content */
    shw ? memcpy(p->arp_sha, shw, ETH_ALEN) : bzero(p->arp_sha, ETH_ALEN);
    dhw ? memcpy(p->arp_tha, dhw, ETH_ALEN) : bzero(p->arp_tha, ETH_ALEN);
    i = htonl(sip);
    memcpy(p->arp_spa, &i, sizeof(i));
    i = htonl(dip);
    memcpy(p->arp_tpa, &i, sizeof(i));

    /* set socket_addr */
	memset(&sa, 0,sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = get_iface_index(skfd, ifname);
    if (sa.sll_ifindex < 0) {
        err("iface index invalid\n");
        close(skfd);
        return -1;
    }

	ret = sendto(skfd, p, sizeof(*p), 0, (struct sockaddr *)&sa, sizeof(sa));
	if (ret != sizeof(*p)) {
        err("sendto failed: %m. ret = %d\n", ret);
		close(skfd);
        return -1;
	}

    close(skfd);
	return ret;
}

////////////////////////////////////////////////////////////////////////////////

/*
 * broadcast request
 * sIP = 0.0.0.0
 * dIP = IP to probe
 * sHW = iface HW
 * dHW = 00.00.00.00.00.00
 *
 * @ip: IP to probe
 * @mac: @ifname's MAC address
 */
int arp_send_probe(char *ifname, uint32_t ip, uint8_t *mac)
{
    info("%s(): ifname = %s, ip = 0x%08x, mac = %s \n", __func__,
			ifname, ip, mac);

    if (ifname == NULL || mac == NULL) {
        err("invalid parameter\n");
        return -1;
    }
    return send_arp(ifname, 0, mac, ip, NULL, ARPOP_REQUEST);
}

/*
 * GARP. broadcast request
 * sIP = IP to announce
 * dIP = IP to announce
 * sHW = iface HW
 * dHW = 00.00.00.00.00.00
 *
 * @ip: IP to announce
 * @mac: @ifname's MAC address
 */
int arp_send_annce(char *ifname, uint32_t ip, uint8_t *mac)
{
    info("%s()\n", __func__);

    if (ifname == NULL || mac == NULL) {
        err("invalid parameter\n");
        return -1;
    }
    return send_arp(ifname, ip, mac, ip, 0, ARPOP_REQUEST);
}

/*
 * same as announcement
 */
int arp_send_defend(char *ifname, uint32_t ip, uint8_t *mac)
{
    info("%s()\n", __func__);

    if (ifname == NULL || mac == NULL) {
        err("invalid parameter\n");
        return -1;
    }
    return send_arp(ifname, ip, mac, ip, 0, ARPOP_REQUEST);
}

