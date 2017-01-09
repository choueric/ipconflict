#ifndef _ARP_LISTTEN_H
#define _ARP_LISTTEN_H

#include "arp_send.h"

/*
 * initiate arp listen environment
 * @return: 0, ok; other, failed
 */
int arp_listen_init();

/* TODO: add remove_listen_iface() */
int arp_listen_add_iface(char *ifname, int is_defend);

#endif
