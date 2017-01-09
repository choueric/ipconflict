#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>
#include <pthread.h>

#include "ipcflt.h"

#include "ipconflict.h"
#include "eloop.h"
#include "arp_listen.h"
#include "us_comm.h"
#include "util.h"

static struct ipcflt_cfg defConfig = {
    300, 3, 1000,
    2000, 2, 2000,
    5000,
    NULL,
	0,
};

int ipcflt_init(struct ipcflt_cfg *cfg)
{
    int ret = 0;
    pthread_t pid;

    if (cfg == NULL)
        cfg = &defConfig;
    set_ipclt_config(cfg);

    eloop_init(NULL);

    if ( (ret = arp_listen_init()) != 0) {
        err("init arp listen failed\n");
        return ret;
    }

    if ( (ret = us_comm_init()) != 0) {
        err("init arp listen failed\n");
        return ret;
    }

    /* will run forever */
    if ( (ret = pthread_create(&pid, NULL, eloop_run, NULL)) != 0) {
        err("pthread_create failed: %m\n");
        return ret;
    }

	info("ipcflt initiate OK.\n");
    return 0;
}

int ipcflt_add_iface(char *ifname, int is_defend)
{
    if (ifname == NULL) {
        err("invalid parameter\n");
        return -1;
    }

    return arp_listen_add_iface(ifname, is_defend);
}

int ipcflt_check_avail(char *ifname, int ip)
{
    int ret = 0;
    int result = 0;
	int reply = 0;
    char buf[IFNAMSIZ + sizeof(int)] = {0};
    int fd = 0;
        
    fd = us_client_connect();
    if (fd < 0) {
        err("open connect to ctrl_iface failed\n");
        return fd;
    }

    strncpy(buf, ifname, IFNAMSIZ);
    strncpy(buf + IFNAMSIZ, (char *)&ip, sizeof(ip));
    ret = us_client_send(fd, buf, sizeof(buf));
    if (ret < 0) {
        err("send_cmd failed\n");
        us_client_disconnect(fd);
        return ret;
    }

    ret = us_client_recv(fd, (char *)&reply, sizeof(reply));
    if (ret < 0) {
        err("recv_reply failed\n");
        us_client_disconnect(fd);
        return ret;
    }
    info("recv_reply\n");
    us_client_disconnect(fd);

    if (ret != sizeof(result)) {
        err("reply buffer size wrong: %d\n", ret);
        return -1;
    }
    result = reply;

    return result;
}

int ipcflt_set_callback(ipcflt_notify callback)
{
    int ret = 0;
    struct ipcflt_cfg *cfg = NULL;

    cfg = get_ipclt_config();
    if (cfg == NULL)
        return -1;

    cfg->notify = callback;
    return ret;
}

int ipcflt_config(enum ipcflt_key key, int val)
{
    int ret = 0;
    struct ipcflt_cfg *cfg = NULL;

    cfg = get_ipclt_config();
    if (cfg == NULL)
        return -1;

    switch (key) {
        case KEY_PROBE_WAIT:
            cfg->probe_wait = val;
            break;
        case KEY_PROBE_NUM:
            cfg->probe_num = val;
            break;
        case KEY_PROBE_INTERVAL:
            cfg->probe_interval = val;
            break;
        case KEY_ANNCE_WAIT:
            cfg->annce_wait = val;
            break;
        case KEY_ANNCE_NUM:
            cfg->annce_num = val;
            break;
        case KEY_ANNCE_INTERVAL:
            cfg->annce_interval = val;
            break;
        case KEY_DEFEND_INTERVAL:
            cfg->defend_interval = val;
            break;
		case KEY_DEBUG_LEVEL:
			cfg->dbg_level = val;
			break;
        default:
            ret = -2;
            break;
    }

    return ret;
}
