#pragma once

#include "ipcflt.h"

/*
 * set ipconflict configuation by @cfg
 */
int set_ipclt_config(struct ipcflt_cfg *cfg);

/*
 * get global ipconflict configuration
 */
struct ipcflt_cfg *get_ipclt_config();

/*
 * detect @ip on interface @ifname whether available in the subnet
 * @cli_fd is used to send result to client.
 */
int probe_check_available(int cli_fd, char *ifname, int ip);

/*
 * this function is called in arp_listen module to check whether the received
 * arp packet is conlicted with IP and Iface which are being probed by 
 * detect_available().
 *
 * @item is the arp packet to be checked, @data is check_state.
 * @return: 0: available; 1: conflict; < 0: error
 */
int listen_check_available(struct arp_item *item, void *data);

int get_dbg_level();
