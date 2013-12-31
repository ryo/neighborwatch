#ifndef _OUI_H_
#define _OUI_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#endif

void oui_reload(void);
const char *oui_lookup(struct ether_addr *);

#endif /* _OUI_H_ */
