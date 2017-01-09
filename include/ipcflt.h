#pragma once

#include <stdint.h>
#include <net/ethernet.h>

struct arp_item {
    uint32_t sip;           // source IP
    uint32_t dip;           // destination IP
    uint8_t shw[ETH_ALEN];  // source hardware address
    uint8_t dhw[ETH_ALEN];  // destination hardware address
};
    
typedef int (*ipcflt_notify)(char *devname, struct arp_item *item);

struct ipcflt_cfg {
    int probe_wait;
    int probe_num;
    int probe_interval;
    int annce_wait;
    int annce_num;
    int annce_interval;
    int defend_interval;
    ipcflt_notify notify;

	int dbg_level;    // 0(error), 1(war), 2(info)
};

enum ipcflt_key {
    KEY_PROBE_WAIT,
    KEY_PROBE_NUM,
    KEY_PROBE_INTERVAL,
    KEY_ANNCE_WAIT,
    KEY_ANNCE_NUM,
    KEY_ANNCE_INTERVAL,
    KEY_DEFEND_INTERVAL,

	KEY_DEBUG_LEVEL,
};


/*
 * @cfg: if @cfg is NULL, use default configuration:
 * static struct ipcflt_cfg default_cfg = {
 *  .probe_wait = 300;
 *  .probe_num = 3;
 *  .probe_interval = 1000;
 *  .annce_wait = 2000;
 *  .annce_num = 2;
 *  .annce_interval = 2000;
 *  .defend_interval = 5000;
 *  .notify = NULL;
 *  };
 */
int ipcflt_init(struct ipcflt_cfg *cfg);

/*
 * set callback to @callback, it will be called when ip conflict happens.
 */
int ipcflt_set_callback(ipcflt_notify callback);

/*
 * set configuraton speicfied by @key to @val
 */
int ipcflt_config(enum ipcflt_key key, int val);

/*
 * add interface to listen
 * @ifname: name of interface, e.g. "eth0"
 * @is_defend: wheather to defend when conflict happend for this iface
 */
int ipcflt_add_iface(char *ifname, int is_defend);

/*
 * @return: 0, available; 1, conflict; < 0, error
 * command format is [IFNAMEA, IP].
 * IFNAME is a string whose length is IFNAMSIZ; IP's lenght is 4.
 */
int ipcflt_check_avail(char *ifname, int ip);
