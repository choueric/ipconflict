#pragma once

#define IPCONFLICT_PATH "/tmp/ipconflict"

/* unix socket communication. Server and Client */

/*
 * initiate control iface's server
 */
int us_comm_init();

/*
 * send reply to client
 */
int us_server_reply(int skfd, char *buf, int len);

/*
 * open connection to ctrl_iface, specified by IPCONFLICT_PATH
 * @return: socket fd when success, otherwise return value < 0
 */
int us_client_connect();

/*
 * send command to server
 * @return: byte number sent when success, otherwise return value < 0
 */
int us_client_send(int skfd, char *buf, int len);

/*
 * receive reply from server
 * @return: byte number received when success, otherwise return value < 0
 */
int us_client_recv(int skfd, char *buf, int len);

/*
 * close connetion to server
 */
int us_client_disconnect(int skfd);
