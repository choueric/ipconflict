#include <sys/socket.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/un.h>
#include <errno.h>
#include <net/if.h>
#include <net/if.h>
#include <unistd.h>

#include "us_comm.h"
#include "eloop.h"
#include "util.h"
#include "ipconflict.h"

////////////////////////////////////////////////////////////////////////////////
//  server
////////////////////////////////////////////////////////////////////////////////

/*
 * handler for control iface server's socket read, register in eloop.
 * interface communicat with outside for ip conlict control.
 * now, the command sent from client is only one, which is [IFNAMEA, IP].
 * IFNAME is a string whose length is IFNAMSIZ; IP's lenght is 4.
 */
static void us_server_handler(int skfd, void *eloop_ctx, void *sock_ctx)
{
    struct sockaddr_un cli_addr;
    socklen_t len = 0;
    int cli_fd, n;
    char buf[128] = {0};
    int ip;

L_AGAIN:
    len = sizeof(cli_addr);
    if ( (cli_fd = accept(skfd, (struct sockaddr *)&cli_addr, &len)) < 0) {
        if (errno == EINTR)
            goto L_AGAIN;
        else {
            err("ctrl_iface: accept failed: %m\n");
            return;
        }
    }

    n = read(cli_fd, buf, sizeof(buf));
    if (n < 0) {
        err("ctrl_iface: handler read failed: %m\n");
        close(cli_fd);
        return;
    }

    /* parse command [IFNAME, IP] */
    if (n != (sizeof(int) + IFNAMSIZ)) {
        err("ctrl_iface: data len is not match length: %d\n", n);
        n = -1;
        // cancel client side's block wait, return failed value
        us_server_reply(cli_fd, (char *)&n, sizeof(n));
        close(cli_fd);
        return;
    }
    ip = *((int *)(buf + IFNAMSIZ));
    probe_check_available(cli_fd, buf, ip);
}


int us_comm_init()
{
    struct sockaddr_un addr;
    int skfd = 0;
    int ret = 0;

    skfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (skfd < 0) {
        err("socket failed: %m\n");
        return skfd;
    }

    unlink(IPCONFLICT_PATH);
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strcpy(addr.sun_path, IPCONFLICT_PATH);

    ret = bind(skfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        err("bind %s failed: %m\n", addr.sun_path);
        close(skfd);
        return ret;
    }

    ret = listen(skfd, 10);
    if (ret < 0) {
        err("listen failed: %m\n");
        close(skfd);
        return ret;
    }
    
    return eloop_register_read_sock(skfd, us_server_handler, 0, 0);
}

int us_server_reply(int skfd, char *buf, int len)
{
    return write(skfd, buf, len);
}

////////////////////////////////////////////////////////////////////////////////
// client
////////////////////////////////////////////////////////////////////////////////

/*
 * open connection to ctrl_iface (i.e. server), specified by IPCONFLICT_PATH
 */
int us_client_connect()
{
    int skfd;
    struct sockaddr_un serv_addr;
    int ret;

    skfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (skfd < 0) {
        err("socket failed: %m\n");
        return skfd;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sun_family = AF_LOCAL;
    strcpy(serv_addr.sun_path, IPCONFLICT_PATH);

    ret = connect(skfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        err("connect failed: %m\n");
        return ret;
    }

    return skfd;
}

int us_client_send(int skfd, char *buf, int len)
{
    int ret = 0;

    if (buf == NULL || len <= 0) {
        err("invalid parameter\n");
        return -1;
    }

    ret = write(skfd, buf, len);
    if (ret < 0) {
        err("write failed: %m\n");
    } else if (ret != len) {
        err("write less than %d/%d\n", len, ret);
    }

    return ret;
}

int us_client_recv(int skfd, char *buf, int len)
{
    int ret = 0;

    if (buf == NULL || len <= 0) {
        err("invalid parameter\n");
        return -1;
    }

    ret = read(skfd, buf, len);
    if (ret < 0) {
        err("read failed: %m\n");
        return ret;
    }

    return ret;
}

int us_client_disconnect(int skfd)
{
    return close(skfd);
}
