#include <stdio.h>
#include <unistd.h>

#include "ipcflt.h"
#include "address.h"

int callback(char *devname, struct arp_item *item)
{
    printf("--> detect ip conflic on iface %s:\n", devname);
    printf("    source ip = %x, source mac = %s\n", item->sip, item->shw);
    printf("    dest   ip = %x, dest   mac = %s\n", item->dip, item->dhw);
    return 0;
}


int main(int argc, char **argv)
{
	ipcflt_init(NULL);
	ipcflt_set_callback(callback);

	ipcflt_config(KEY_DEBUG_LEVEL, 1);

	uint32_t ip = 0;
	sa_stoi("192.168.1.10", &ip);

    int ret = ipcflt_check_avail("eth0", ip);
	printf("ret = %d\n", ret);
    if (ret == 0) {
        printf("avilable\n");
    } else if (ret == 1) {
        printf("conflict\n");
    } else {
        printf("error\n");
		return -1;
    }

    ipcflt_add_iface("eth0", 0);

    while (1)
        sleep(1);
    return 0;
}
