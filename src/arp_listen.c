#include <stdio.h>
#include <net/if.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <strings.h>

#include "arp_listen.h"
#include "ipconflict.h"
#include "eloop.h"
#include "util.h"

#define ARP_BUF_SIZE 256

struct ifdev {
	char name[IFNAMSIZ];    /* Device name */
	int is_usable;          /* Indicate if device can be used in conflict detection process */
	uint32_t ip;            /* IP address of device */
	uint8_t mac[ETH_ALEN];  /* MAC address of device */
	int is_defend;          /* IPwatch mode on interface */
	struct timeval time;    /* Time when the last conflict was detected */
    struct ifdev *next;
};

struct ifdev_list {
    struct ifdev *dev;
    int num;
    pthread_mutex_t lock;
};

static char g_arp_buf[ARP_BUF_SIZE];
static struct ifdev_list g_iflist;

static void print_arp_packet(FILE *fp, struct arp_packet *p)
{
	if (get_dbg_level() < 2)
		return;
	char str[32];
	struct in_addr *addr = NULL;

	addr = (struct in_addr *)p->arp_spa;
	fprintf(fp, "sip = %s\t", inet_ntop(AF_INET, addr, str, 32));
	addr = (struct in_addr *)p->arp_tpa;
	fprintf(fp, "dip = %s\t", inet_ntop(AF_INET, addr, str, 32));
	fprintf(fp, "shw = %s\t", hwaddr_bin2str(p->arp_sha, str, 32));
	fprintf(fp, "dhw = %s\n", hwaddr_bin2str(p->arp_tha, str, 32));
}

static void print_arp_item(struct arp_item *item)
{
	if (get_dbg_level() < 2)
		return;

	char str[32];
	printf("sip = %s\t", ipc_sa_itos(item->sip, str, 32));
	printf("dip = %s\t", ipc_sa_itos(item->dip, str, 32));
	printf("shw = %s\t", hwaddr_bin2str(item->shw, str, 32));
	printf("dhw = %s\n", hwaddr_bin2str(item->dhw, str, 32));
}

static void print_iflist(struct ifdev_list *list)
{
    pthread_mutex_lock(&list->lock);

    printf("-------- %d -------\n", list->num);
    struct ifdev *dev = list->dev;
    while (dev) {
        printf("%s\n", dev->name);
        dev = dev->next;
    }

    pthread_mutex_unlock(&list->lock);
}

/*
 * check @ifname is already existed in @list
 * @return: 0, not existed; 1, existed.
 */
static int is_ifdev_existed(char *ifname, struct ifdev_list *list)
{
    pthread_mutex_lock(&list->lock);

    struct ifdev *dev = NULL;
    for (dev = list->dev; dev; dev = dev->next) {
        if (!strcmp(ifname, dev->name)) {
            return 1;
        }
    }

    pthread_mutex_unlock(&list->lock);

    return 0;
}

/*
 * convert struct arp_packet to struct arp_item
 */
static void parse_arp_info(struct arp_item *item, struct arp_packet *p)
{
	uint32_t *pp = (uint32_t *)p->arp_spa;
    item->sip = ntohl(*pp);
    pp = (uint32_t*)p->arp_tpa;
    item->dip = ntohl(*pp);
    memcpy(item->shw, p->arp_sha, ETH_ALEN);
    memcpy(item->dhw, p->arp_tha, ETH_ALEN);
}

/*
 * @return: 0, success; other, failed.
 */
static int get_ifdev_info(char *ifname, uint32_t *p_ip, uint8_t *p_mac)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		err("Could not open socket: %m\n");
		return -1;
	}

	bzero(&ifr, sizeof(struct ifreq));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	/* Get IP address of interface */
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		/* Do not log error for interfaces without IP address */
		if (errno == EADDRNOTAVAIL) {
			close (sock);
			return -1;
		}
		err("Could not get IP of the device %s: %m\n", ifname);
		close (sock);
		return -2;
	}

    struct sockaddr *p = &ifr.ifr_addr;
    struct sockaddr_in *s = (struct sockaddr_in *)p;
    *p_ip = ntohl(s->sin_addr.s_addr);

	/* Get MAC address of interface */
	if (ioctl (sock, SIOCGIFHWADDR, &ifr) < 0) {
		err("Could not get MAC of the device %s: %m\n", ifname);
		close (sock);
		return -1;
	}
    memcpy(p_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	close (sock);
	return 0;
}

/*
 * return 1 means arp packet @item is from local interface or machine
 */
static int update_and_check_local(struct arp_item *item, struct ifdev_list *list)
{
    struct ifdev *dev = NULL;

    for (dev = list->dev; dev; dev = dev->next) {
        dev->is_usable = get_ifdev_info(dev->name, &dev->ip, dev->mac) ? 0: 1;
        if (dev->is_usable == 0) 
            continue;
		/* Ignore packets coming from local interfaces */
        if (is_hwaddr_same(item->shw, dev->mac)) {
			if (item->sip == dev->ip)
				warn("ARP packet ignored because it comes from local interface.\n");
			else
				/* Happens when there is more than one interface connected to the same subnet */
				warn("ARP packet ignored because it comes from local machine's other interface.\n");
            return 1;
        }
    }

    return 0;
}

/*
 * @return: 0, not conflict; 1, conflict
 */
static int do_check_conflict(struct arp_item *item, struct ifdev_list *list)
{
    int diff = 0, ret = 0;
    struct ifdev *dev = NULL;
	struct timeval cur_time;
    struct ipcflt_cfg *cfg = get_ipclt_config();
    char ipstr[32];
    char macstr[32];

    for (dev = list->dev; dev; dev = dev->next) {
        if (dev->is_usable == 0) {
            continue;
        }

        /* Check if received packet causes conflict with IP of this interface */
        if ((item->sip != dev->ip) || is_hwaddr_same(item->shw, dev->mac)) {
            continue; // not conflict
        }

        gettimeofday(&cur_time, NULL);

        if (dev->time.tv_sec == 0) {
            info("MAC %s conflict with IP %s on %s - no action taken because it's the first time\n",
					hwaddr_bin2str(item->shw, macstr, 32), ipc_sa_itos(dev->ip, ipstr, 32),
					dev->name);
            dev->time.tv_sec = cur_time.tv_sec;
            dev->time.tv_usec = cur_time.tv_usec;
            break;
        }

        diff = (cur_time.tv_sec-dev->time.tv_sec)*1000+(cur_time.tv_usec-dev->time.tv_usec)/1000;
        info("iface [%s] conflict, diff = %dms, interval = %dms\n",
				dev->name, diff, cfg->defend_interval);
        if (diff < cfg->defend_interval) {
            info("MAC %s conflict with IP %s on %s - no action taken within the defend interval\n",
                    hwaddr_bin2str(item->shw, macstr, 32), ipc_sa_itos(dev->ip, ipstr, 32),
					dev->name);
            break;
        }

        /* Store conflict time */
        dev->time.tv_sec = cur_time.tv_sec;
        dev->time.tv_usec = cur_time.tv_usec;

        /* Handle IP conflict */
        if (dev->is_defend) {
            info("MAC %s conflict with IP %s on %s - defend\n",
					hwaddr_bin2str(item->shw, macstr, 32), 
                    ipc_sa_itos(dev->ip, ipstr, 32), dev->name);

            /* Send reply to conflicting system */
            /* Send GARP request to update cache of our neighbours */
            arp_send_defend(dev->name, dev->ip, dev->mac);
        } else {
            info("MAC %s conflict with IP %s on %s - no defend\n",
					hwaddr_bin2str(item->shw, macstr, 32),
                    ipc_sa_itos(dev->ip, ipstr, 32), dev->name);
        }

        if (cfg->notify)
            cfg->notify(dev->name, item);
        ret = 1;
    }

    return ret;
}

static int check_available_when_listen(struct arp_item *item, struct eloop_timeout *head)
{
    int ret = 0;
    struct eloop_timeout *node;

    for (node = head; node != NULL; node = node->next) {
        ret = listen_check_available(item, node->user_data);
    }

    return ret;
}

static int check_arp_conflict(struct arp_packet *p)
{
    struct ifdev_list *list = &g_iflist;
    struct arp_item item;
    struct eloop_timeout *t = NULL;

    parse_arp_info(&item, p);

	print_arp_item(&item);
	print_arp_packet(stdout, p);

    t = eloop_get_timeout_table();
    if (t)
        check_available_when_listen(&item, t);

    if (update_and_check_local(&item, list)) {
        info("arp packet is from local host\n");
        return 0;
    }

    return do_check_conflict(&item, list);
}

static void arp_handler(int skfd, void *eloop_ctx, void *sock_ctx)
{
    char *buf = (char *)sock_ctx;
    int ret = 0;

    ret = recvfrom(skfd, buf, ARP_BUF_SIZE, 0, NULL, NULL);
    if (ret < 0) {
        err("recvfrom fail: %m\n");
        return;
    } else if ( ret < sizeof(struct arp_packet)) {
        err("recvfrom has not enough data for arp packet %d\n", ret);
        return;
    }
    //dump_mem(buf, ret);
    check_arp_conflict((struct arp_packet *)buf);
}

////////////////////////////////////////////////////////////////////////////////

/*
 * initiate arp listen
 * @return: 0, ok; other, failed
 */
int arp_listen_init()
{
    int skfd;
    struct ifdev_list *list = &g_iflist;

    list->dev = NULL;
    list->num = 0;
    pthread_mutex_init(&(list->lock), NULL);

    skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (skfd < 0) {
        err("socket failed: %m\n");
        return skfd;
    }

    return eloop_register_read_sock(skfd, arp_handler, NULL, g_arp_buf);
}

int arp_listen_add_iface(char *ifname, int is_defend)
{
    struct ifdev_list *list = &g_iflist;
    struct ifdev *dev = NULL;
    struct ifdev *tmp = NULL;

    if (ifname == NULL) {
        err("invalid parameter\n");
        return -1;
    }

    if (strlen(ifname) >= IFNAMSIZ) {
        err("%s is too long\n", ifname);
        return -1;
    }

    if (is_ifdev_existed(ifname, list)) {
        err("%s is already existed in list\n");
        return -2;
    }

    dev = malloc(sizeof(struct ifdev));
    if (dev == NULL) {
        err("new struct ifdev failed: %m\n");
        return -1;
    }

    bzero(dev, sizeof(*dev));
    strncpy(dev->name, ifname, IFNAMSIZ);
    dev->is_usable = 0;
    dev->is_defend = is_defend;
    dev->time.tv_sec = 0;
    dev->time.tv_usec = 0;

    pthread_mutex_lock(&list->lock);
    if (list->dev == NULL) {
        list->dev = dev;
    } else {
        tmp = list->dev;
        dev->next = tmp;
        list->dev = dev;
    }
    list->num++;
    pthread_mutex_unlock(&list->lock);

    print_iflist(list);
    return 0;
}
