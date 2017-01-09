#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "us_comm.h"
#include "eloop.h"
#include "ipconflict.h"
#include "util.h"
#include "arp_send.h"
#include "arp_listen.h"

/* global configuration */
static struct ipcflt_cfg gConfig;

struct check_state {
    struct ipcflt_cfg *cfg;
	eloop_timeout_handler handler;

    char ifname[IFNAMSIZ];
    uint8_t hwaddr[ETH_ALEN];
    uint32_t ip;

    int probe_count;
    int annce_count;
    int fd;
    int result;  // 0: available; 1: conflict; < 0: other error.
};

static void print_probe_conflict(struct check_state *s, struct arp_item *item)
{
	if (get_dbg_level() < 2)
		return;

    char str[32];

    printf("--- conflict when probe ---\n");
    printf("IP = %s, ", ipc_sa_itos(s->ip, str, 32));
    printf("MAC = %s", hwaddr_bin2str(s->hwaddr, str, 32));
    printf(" <--> %s\n", hwaddr_bin2str(item->shw, str, 32));
}

static int iface_get_mac(char *ifname, uint8_t *hwaddr, int len)
{
    struct ifreq ifr;
    int ret = 0;
    int skfd = 0;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0) {
        printf("open socket failed: %m\n");
        return -1;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        memset(hwaddr, 0, len);
        ret = -1;
        fprintf(stderr, "%s: SIOCGIFHWADDR: %s\n", ifname, strerror(errno));
    } else {
        memmove(hwaddr, ifr.ifr_hwaddr.sa_data, 8);
        ret = 0;
    }

    close(skfd);
    return ret;
}

static void check_handler(void *eloop_data, void *user_ctx)
{
    struct check_state *s = (struct check_state *)user_ctx;
    struct ipcflt_cfg *cfg = s->cfg;
    int timeout;
    int ret;

    /* probe phase */
    if (s->probe_count < cfg->probe_num) {
        arp_send_probe(s->ifname, s->ip, s->hwaddr);
        s->probe_count++;
        if (s->probe_count == cfg->probe_num)
            timeout = cfg->annce_wait;
        else
            timeout = cfg->probe_interval;
        eloop_register_timeout(0, timeout * 1000, s->handler, NULL, s);
    /* announce phase */
    } else if (s->probe_count == cfg->probe_num
            && s->annce_count < cfg->annce_num) {
        arp_send_annce(s->ifname, s->ip, s->hwaddr);
        s->annce_count++;
        if (s->annce_count == 1) {
            /* reply ok result */
            ret = us_server_reply(s->fd, (char *)&(s->result), sizeof(s->result));
            if (ret < 0) {
                err("chekc_handler: write failed: %m\n");
            }
            close(s->fd);
        }
        eloop_register_timeout(0, cfg->annce_interval * 1000, s->handler, NULL, s);
    /* end of available-check, free resource */
    } else if (s->annce_count == cfg->annce_num) {
       info("end of check_state\n");
       free(s); 
    }
}

////////////////////////////////////////////////////////////////////////////////

/*
 * detect @ip on interface @ifname whether available in the subnet
 * @cli_fd is used to send result to client.
 */
int probe_check_available(int cli_fd, char *ifname, int ip)
{
    int ret = 0;
    struct ipcflt_cfg *cfg = get_ipclt_config();
    char str[32];
    struct check_state *state = NULL;

    if (ifname == NULL) {
        err("invalid parameter\n");
        ret = -2;
        us_server_reply(cli_fd, (char *)&ret, sizeof(ret));
        close(cli_fd);
        return ret;
    }

    state = malloc(sizeof(struct check_state));
    if (state == NULL) {
        err("new op failed: %m\n");
        ret = -3;
        us_server_reply(cli_fd, (char *)&ret, sizeof(ret));
        close(cli_fd);
        return ret;
    }

    bzero(state, sizeof(*state));
    state->cfg = cfg;
    state->probe_count = 0;
    state->annce_count = 0;
    state->ip = ip;
    state->fd = cli_fd;
    state->result = 0;  // default value is available.
    state->handler = check_handler;
    strncpy(state->ifname, ifname, IFNAMSIZ);
    if (iface_get_mac(state->ifname, state->hwaddr, ETH_ALEN) < 0) {
        err("get mac failed\n");
        ret = -4;
        us_server_reply(cli_fd, (char *)&ret, sizeof(ret));
        close(cli_fd);
        free(state);
        return ret;
    }

    info("%s(): going to check [%s] if available on iface [%s]\n", __func__, 
            ipc_sa_itos(state->ip, str, sizeof(str)), state->ifname);

    eloop_register_timeout(0, cfg->probe_wait * 1000, state->handler,
            NULL, state);

    return 0;
}

/*
 * this function is called in arp_listen module to check whether the received
 * arp packet is conlicted with IP and Iface which are being probed by 
 * detect_available().
 *
 * @item is the arp packet to be checked, @data is check_state.
 * @return: 0: available; 1: conflict; < 0: error
 */
int listen_check_available(struct arp_item *item, void *data)
{
    int res = 0;
    struct check_state *s = (struct check_state *)data;
    uint8_t zeromac[ETH_ALEN] = {0};

    if (data == NULL)
        return -1;

    /* not start probing or end of probing */
    if (s->probe_count == 0 || s->annce_count > 1)
        return 0;

    /* from same iface */
    if (is_hwaddr_same(item->shw, s->hwaddr)) {
        return 0;
    }

    if (item->sip == s->ip) {
        warn("some host is using IP %08x\n", s->ip);
        res = 1;
    }
    if ((item->dip == s->ip) && is_hwaddr_same(item->dhw, zeromac)) {
        warn("some host is probing IP %08x\n", s->ip);
        res = 1;
    }

    if (res == 0)
        return 0;

    print_probe_conflict(s, item);

    s->result = 1;
    us_server_reply(s->fd, (char *)&(s->result), sizeof(s->result));
    close(s->fd);
    eloop_cancel_timeout(s->handler, NULL, s);
    free(s);

    return res;
}

int set_ipclt_config(struct ipcflt_cfg *cfg)
{
    if (cfg == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    memcpy(&gConfig, cfg, sizeof(*cfg));
    return 0;
}

struct ipcflt_cfg *get_ipclt_config()
{
    return &gConfig;
}

int get_dbg_level()
{
	return gConfig.dbg_level;
}
