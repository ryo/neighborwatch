/*	$Id: neighborwatch_bpf.c,v 1.7 2013/12/27 14:54:41 ryo Exp $	*/

/*-
 * Copyright (c) 2013 SHIMIZU Ryo <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <net/if_arp.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#endif
#include <net/bpf.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include "neighborwatch.h"
#include "packet.h"

static int bpfslot(void);
static int bpfopen(const char *, int, unsigned int *, int);
static int bpf_apply_filter(int);
#if 0
static int bpf_available(int);
static int getifinfo(const char *, int *, uint8_t *);
#endif

struct bpf_insn arp_or_nd_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_VLAN, 16 /* #VLAN */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 9 /* #ARP */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0 /* #IPV6 */, 13 /* #NOMATCH */),
/* #IPV6 */
	/* fetch ip6_hdr->ip6_nxt */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 6),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0 /* #ICMP6 */, 11 /* #NOMATCH */),
/* #ICMP6 */
	/* fetch icmp6_hdr->icmp6_type */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + sizeof(struct ip6_hdr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_SOLICIT, 3 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_ADVERT, 2 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 1 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 6 /* #NOMATCH */),
/* #NEIGHBOR_DISCOVERY */
	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
/* #ARP */
	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3 /* #NOMATCH */),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REQUEST, 0, 1 /* #NOMATCH */),
	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
/* #NOMATCH */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */


/* #VLAN */
	/* check ethertype in vlan */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_HDR_LEN + 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 9 /* #ARP */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0 /* #IPV6 */, 13 /* #NOMATCH */),
/* #IPV6 */
	/* fetch ip6_hdr->ip6_nxt */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN + 6),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0 /* #ICMP6 */, 11 /* #NOMATCH */),
/* #ICMP6 */
	/* fetch icmp6_hdr->icmp6_type */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN + sizeof(struct ip6_hdr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_SOLICIT, 3 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_ADVERT, 2 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 1 /* #NEIGHBOR_DISCOVERY */, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 6 /* #NOMATCH */),
/* #NEIGHBOR_DISCOVERY */
	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
/* #ARP */
	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3 /* #NOMATCH */),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REQUEST, 0, 1 /* #NOMATCH */),
	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 (whole of packet) */
/* #NOMATCH */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};


static int
bpfslot()
{
	int fd, i;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[MAXPATHLEN + 1];

	memset(devbpf, 0, sizeof(devbpf));
	i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

static int
bpf_apply_filter(int fd)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));
	bpfprog.bf_len = sizeof(arp_or_nd_filter) / sizeof(arp_or_nd_filter[0]);
	bpfprog.bf_insns = arp_or_nd_filter;
	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		logging(LOG_WARNING, "ioctl: BIOCSETF: %s", strerror(errno));

	return rc;
}

static int
bpfopen(const char *ifname, int promisc, unsigned int *buflen, int with_log)
{
	int fd, flag, rc;
	struct ifreq ifr;
	struct bpf_version bv;

	rc = 0;
	fd = bpfslot();
	if (fd < 0) {
		logging(LOG_ERR, "open: bpf: %s", strerror(errno));
		rc = -1;
		goto bpfopen_err;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		logging(LOG_ERR, "ioctl: BIOCVERSION: %s", strerror(errno));
		rc = -1;
		goto bpfopen_err;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		logging(LOG_ERR, "kernel bpf filter out of date");
		rc = -1;
		goto bpfopen_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (ifname != NULL) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
			if (with_log) {
				logging(LOG_WARNING, "ioctl: %s: BIOCSETIF: %s", ifname,
				    strerror(errno));
			}
			rc = -2;
			goto bpfopen_warn;
		}
	}

	flag = 1;
	ioctl(fd, BIOCIMMEDIATE, &flag);

	if (promisc) {
		if (ioctl(fd, BIOCPROMISC, 0) != 0) {
			logging(LOG_NOTICE, "ioctl: BIOCPROMISC: %s: %s", ifname,
			    strerror(errno));
		}
	}

	ioctl(fd, BIOCSBLEN, buflen);
	ioctl(fd, BIOCGBLEN, buflen);	/* return value for caller */

	return fd;

 bpfopen_warn:
 bpfopen_err:
	if (fd >= 0)
		close(fd);

	return rc;
}

#if 0
static int
bpf_available(int fd)
{
	unsigned int buflen;

	return ioctl(fd, BIOCGBLEN, &buflen);
}

static int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int mib[6] = {
		CTL_NET,
		AF_ROUTE,
		0,
		AF_LINK,
		NET_RT_IFLIST,
		0
	};
	uint8_t *buf, *end, *msghdr;
	struct if_msghdr *ifm;
	struct if_data *ifd = NULL;
	struct sockaddr_dl *sdl;
	size_t len;
	int rc;

	rc = -1;
	buf = NULL;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		logging(LOG_ERR, "sysctl: %s: cannot get iflist size",
		    strerror(errno));
		goto getifinfo_done;
	}
	if ((buf = malloc(len)) == NULL) {
		logging(LOG_ERR, "cannot allocate memory");
		goto getifinfo_done;
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		logging(LOG_ERR, "sysctl: %s: cannot get iflist",
		    strerror(errno));
		goto getifinfo_done;
	}

	end = buf + len;
	for (msghdr = buf; msghdr < end; msghdr += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)msghdr;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);

			if (sdl->sdl_type != IFT_ETHER)
				continue;
			if (strncmp(&sdl->sdl_data[0], ifname, sdl->sdl_nlen)
			    != 0)
				continue;


			ifd = &ifm->ifm_data;
			if (mtu != NULL)
				*mtu = ifd->ifi_mtu;
			memcpy(hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			rc = 0;
			break;
		}
	}
	if (rc != 0)
		logging(LOG_ERR,
		    "%s: Not a ethernet interface or no such interface",
		    ifname);

 getifinfo_done:
	if (buf != NULL)
		free(buf);

	return rc;
}
#endif

int
neighborwatch_open(const char *ifname, int promisc, unsigned int *buflen, int with_log)
{
	int fd;

	fd = bpfopen(ifname, promisc, buflen, with_log);

	if ((fd < 0) && neighborwatch_debug) {
		logging(LOG_DEBUG, "open: bpf: %s: fd=%d",
		    ifname, fd);
		return -1;
	}

	if (bpf_apply_filter(fd) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

void
neighborwatch_close(int fd)
{
	close(fd);
}

int
pktread_and_exec(void (*execfunc)(void *, unsigned char *, int, const char *),
    void *arg, int fd, const char *ifname,
    unsigned char *buf, int buflen)
{
	ssize_t rc;

	rc = read(fd, buf, buflen);
	if (rc == 0) {
		logging(LOG_ERR, "bpfread: no data");
	} else if (rc < 0) {
		logging(LOG_ERR, "bpfread: %s", strerror(errno));
	} else {
		uint8_t *p = buf;
		uint8_t *end = p + rc;

		while (p < end) {
			unsigned int perpacketsize =
			    ((struct bpf_hdr*)p)->bh_hdrlen +
			    ((struct bpf_hdr*)p)->bh_caplen;

			execfunc(arg,
			    ((uint8_t *)p + ((struct bpf_hdr*)p)->bh_hdrlen),
			    ((struct bpf_hdr*)p)->bh_datalen, ifname);

			p += BPF_WORDALIGN(perpacketsize);
		}
	}

	return 0;
}
