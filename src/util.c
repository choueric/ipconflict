#include <stdio.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipconflict.h"

void dp(int level, const char *format, ...)
{
	if (get_dbg_level() < level)
		return;

	char str[128] = {0};
	char *substr = NULL;
	va_list args;
	struct timeval tv;

	va_start(args, format);

	gettimeofday(&tv, NULL);
	snprintf(str, 128, "libipcflt: [%ld.%06ld] ", tv.tv_sec, tv.tv_usec);
	substr = str + strlen(str);
	vsnprintf(substr, 128, format, args);

	va_end(args);

	printf("%s", str);
}

void dump_mem(unsigned char *buf, int size)
{
	int i;

	printf("------------ size = %d ------------------\n", size);
	for (i = 0; i < size; i++) {
		printf("%02x ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

int is_hwaddr_same(uint8_t *a, uint8_t *b)
{
    return ((memcmp(a, b, ETH_ALEN) == 0) ? 1: 0);
}

char *hwaddr_bin2str(uint8_t *ptr, char *str, int len)
{
    memset(str, 0, len);
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
	     (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	     (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)
	);
    return str;
}

const char *ipc_sa_itos(uint32_t ip, char *str, uint32_t size)
{
    struct in_addr addr = {0};
    addr.s_addr = htonl(ip);
    return inet_ntop(AF_INET, &addr, str, (socklen_t)size);
}

