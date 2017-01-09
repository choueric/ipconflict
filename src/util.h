#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

#define err(fmt, args...) dp(0, fmt, ##args)
#define warn(fmt, args...) dp(1, fmt, ##args)
#define info(fmt, args...) dp(2, fmt, ##args)
void dp(int level, const char *format, ...);

void dump_mem(unsigned char *buf, int size);

int is_hwaddr_same(uint8_t *a, uint8_t *b);

char *hwaddr_bin2str(uint8_t *ptr, char *str, int len);

// from netlib
const char *ipc_sa_itos(uint32_t ip, char *str, uint32_t size);
#endif
