/*
 * Event loop based on select() loop
 * Copyright (c) 2002-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "eloop.h"

#define TABLE_SIZE 2  // just for cmd_sockfd and arp_sockfd

#define time_before(a, b) \
    ((a)->tv_sec < (b)->tv_sec || \
     ((a)->tv_sec == (b)->tv_sec && (a)->tv_usec < (b)->tv_usec))

#define time_sub(a, b, res) do {\
    (res)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
    (res)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
    if ((res)->tv_usec < 0) {\
        (res)->tv_sec--;\
        (res)->tv_usec += 1000000;\
    }\
} while (0)

struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
};

struct eloop_sock_table {
	int count;
	struct eloop_sock table[TABLE_SIZE];
};

struct eloop_data {
	void *user_data;

	int max_sock;

	struct eloop_sock_table readers;
	struct eloop_timeout *timeout;

	int terminate;
	int reader_table_changed;
};

////////////////////////////////////////////////////////////////////////////////

static struct eloop_data g_eloop;

////////////////////////////////////////////////////////////////////////////////

int eloop_init(void *user_data)
{
    struct eloop_data *eloop = &g_eloop;

	memset(eloop, 0, sizeof(struct eloop_data));
	eloop->user_data = user_data;
	return 0;
}

static int eloop_sock_table_add_sock(struct eloop_sock_table *table,
                                     int sock, eloop_sock_handler handler,
                                     void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;
    struct eloop_data *eloop = &g_eloop;

	if (table == NULL)
		return -1;

    if (table->count == TABLE_SIZE)
        return -1;

    tmp = &(table->table[table->count]);

	tmp->sock = sock;
	tmp->eloop_data = eloop_data;
	tmp->user_data = user_data;
	tmp->handler = handler;
	table->count++;
	if (sock > eloop->max_sock)
		eloop->max_sock = sock;

	return 0;
}

static void eloop_sock_table_remove_sock(struct eloop_sock_table *table,
                                         int sock)
{
	int i;

	if (table == NULL || table->table == NULL || table->count == 0)
		return;

	for (i = 0; i < table->count; i++) {
		if (table->table[i].sock == sock)
			break;
	}
	if (i == table->count)
		return;
	if (i != table->count - 1) {
		memmove(&table->table[i], &table->table[i + 1],
			   (table->count - i - 1) *
			   sizeof(struct eloop_sock));
	}
	table->count--;
}

static void eloop_sock_table_set_fds(struct eloop_sock_table *table,
				     fd_set *fds)
{
	int i;

	FD_ZERO(fds);

	if (table->table == NULL)
		return;

	for (i = 0; i < table->count; i++)
		FD_SET(table->table[i].sock, fds);
}

static void eloop_sock_table_dispatch(struct eloop_sock_table *table,
				      fd_set *fds)
{
	int i;

	if (table == NULL || table->table == NULL)
		return;

	for (i = 0; i < table->count; i++) {
		if (FD_ISSET(table->table[i].sock, fds)) {
			table->table[i].handler(table->table[i].sock,
						table->table[i].eloop_data,
						table->table[i].user_data);
		}
	}
}

int eloop_register_read_sock(int sock, eloop_sock_handler handler,
			void *eloop_data, void *user_data)
{
	struct eloop_sock_table *table;
    struct eloop_data *eloop = &g_eloop;

	table = &eloop->readers;
	return eloop_sock_table_add_sock(table, sock, handler,
					 eloop_data, user_data);
}

void eloop_unregister_read_sock(int sock)
{
	struct eloop_sock_table *table;
    struct eloop_data *eloop = &g_eloop;

	table = &eloop->readers;
	eloop_sock_table_remove_sock(table, sock);
}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp, *prev;
    struct eloop_data *eloop = &g_eloop;

	timeout = malloc(sizeof(struct eloop_timeout));
	if (timeout == NULL)
		return -1;
    bzero(timeout, sizeof(*timeout));
	if (gettimeofday(&timeout->time, NULL) < 0) {
		free(timeout);
		return -1;
	}
	timeout->time.tv_sec += secs;
	timeout->time.tv_usec += usecs;
	while (timeout->time.tv_usec >= 1000000) {
		timeout->time.tv_sec++;
		timeout->time.tv_usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (eloop->timeout == NULL) {
		eloop->timeout = timeout;
		return 0;
	}

	prev = NULL;
	tmp = eloop->timeout;
	while (tmp != NULL) {
		if (time_before(&timeout->time, &tmp->time))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = eloop->timeout;
		eloop->timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return 0;
}

struct eloop_timeout *eloop_get_timeout_table()
{
    struct eloop_data *eloop = &g_eloop;
    return eloop->timeout;
}

int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev, *next;
    struct eloop_data *eloop = &g_eloop;
	int removed = 0;

	prev = NULL;
	timeout = eloop->timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			if (prev == NULL)
				eloop->timeout = next;
			else
				prev->next = next;
			free(timeout);
			removed++;
		} else
			prev = timeout;

		timeout = next;
	}

	return removed;
}

int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data)
{
	struct eloop_timeout *tmp;
    struct eloop_data *eloop = &g_eloop;

	tmp = eloop->timeout;
	while (tmp != NULL) {
		if (tmp->handler == handler &&
		    tmp->eloop_data == eloop_data &&
		    tmp->user_data == user_data)
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

void *eloop_run(void *data)
{
	int res;
	struct timeval _tv;
	struct timeval tv, now;
	fd_set rfds;
    struct eloop_data *eloop = &g_eloop;

    /*
	rfds = malloc(sizeof(fd_set));
	if (rfds == NULL ) {
		printf("eloop_run - new failed\n");
		goto out;
	}
    */

	while (!eloop->terminate &&
	       (eloop->timeout || eloop->readers.count > 0)) {
		if (eloop->timeout) {
			gettimeofday(&now, NULL);
			if (time_before(&now, &eloop->timeout->time))
				time_sub(&eloop->timeout->time, &now, &tv);
			else
				tv.tv_sec = tv.tv_usec = 0;
			_tv.tv_sec = tv.tv_sec;
			_tv.tv_usec = tv.tv_usec;
		}

		eloop_sock_table_set_fds(&eloop->readers, &rfds);
		res = select(eloop->max_sock + 1, &rfds, NULL, NULL,
			     eloop->timeout ? &_tv : NULL);
		if (res < 0 && errno != EINTR && errno != 0) {
			perror("select");
			goto out;
		}

		/* check if some registered timeouts have occurred */
		if (eloop->timeout) {
			struct eloop_timeout *tmp;

			gettimeofday(&now, NULL);
			if (!time_before(&now, &eloop->timeout->time)) {
				tmp = eloop->timeout;
				eloop->timeout = eloop->timeout->next;
				tmp->handler(tmp->eloop_data,
					     tmp->user_data);
				free(tmp);
			}
		}

		if (res <= 0)
			continue;

        /* handle socket read */
		eloop_sock_table_dispatch(&eloop->readers, &rfds);
	}

out:
	//free(rfds);
	return NULL;
}

void eloop_terminate(void)
{
    struct eloop_data *eloop = &g_eloop;

	eloop->terminate = 1;
}

void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;
    struct eloop_data *eloop = &g_eloop;

	timeout = eloop->timeout;
	while (timeout != NULL) {
		prev = timeout;
		timeout = timeout->next;
		free(prev);
	}
}

int eloop_terminated(void)
{
    struct eloop_data *eloop = &g_eloop;
	return eloop->terminate;
}

void eloop_wait_for_read_sock(int sock)
{
	fd_set rfds;

	if (sock < 0)
		return;

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	select(sock + 1, &rfds, NULL, NULL, NULL);
}

void * eloop_get_user_data(void)
{
    struct eloop_data *eloop = &g_eloop;
	return eloop->user_data;
}
