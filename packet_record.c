/*	$Id: packet_record.c,v 1.10 2013/12/31 19:22:35 ryo Exp $	*/

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
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#include <net/if_vlanvar.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#include <net/if_vlan_var.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#include <net/if_vlan_var.h>
#include <net/if_arp.h>
#endif
#include <stdio.h>

#include "neighborwatch.h"
#include "logdb.h"
#include "packet.h"

static int recorder_arp(struct ether_addr *, struct ether_addr *, uint16_t, int, struct arppkt *, int);
static int recorder_ipv6_nd(struct ether_addr *, struct ether_addr *, uint16_t, int, struct ip6icmp6nd *, int);
static int recorder_unknown(struct ether_addr *, struct ether_addr *, uint16_t, int, uint8_t *, int);

static void dump_eh(struct ether_addr *, struct ether_addr *, uint16_t, int);

static int fdumpstr(FILE *, const char *, size_t);
static int dumpstr(const char *, size_t);

static void
dump_eh(struct ether_addr *dst, struct ether_addr *src, uint16_t type, int vlan)
{
	if (vlan >= 0)
		printf("VLAN %d: ", vlan);

	switch (type) {
	case ETHERTYPE_ARP:
		printf("ARP: ");
		break;
	case ETHERTYPE_IPV6:
		printf("IPv6: ");
		break;
	default:
		printf("%04x: ", type);
		break;
	}

	printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
	    src->ether_addr_octet[0], src->ether_addr_octet[1], src->ether_addr_octet[2],
	    src->ether_addr_octet[3], src->ether_addr_octet[4], src->ether_addr_octet[5],
	    dst->ether_addr_octet[0], dst->ether_addr_octet[1], dst->ether_addr_octet[2],
	    dst->ether_addr_octet[3], dst->ether_addr_octet[4], dst->ether_addr_octet[5]);
}

static int
recorder_arp(struct ether_addr *dst, struct ether_addr *src, uint16_t type, int vlan, struct arppkt *arp, int pktlen)
{
//	dump_eh(dst, src, type, vlan);

	if (arp->ar_hrd == htons(ARPHRD_ETHER) &&
	    arp->ar_pro == htons(ETHERTYPE_IP) &&
	    arp->ar_hln == 6 &&
	    arp->ar_pln == 4) {

#if 0
		switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf("arp request\n");
			break;
		case ARPOP_REPLY:
			printf("arp reply\n");
			break;
		case ARPOP_REVREQUEST:
			printf("rarp request\n");
			break;
		case ARPOP_REVREPLY:
			printf("rarp reply\n");
			break;
		case ARPOP_INVREQUEST:
			printf("identify peer request\n");
			break;
		case ARPOP_INVREPLY:
			printf("identify peer reply\n");
			break;
		default:
			printf("unknown arp op: %02x\n", ntohs(arp->ar_op));
			dumpstr((const char *)arp, pktlen);
			break;
		}
		printf("	sha=%02x:%02x:%02x:%02x:%02x:%02x\n",
		    arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2],
		    arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
		printf("	spa=%s\n", inet_ntoa(arp->ar_spa));
		printf("	tha=%02x:%02x:%02x:%02x:%02x:%02x\n",
		    arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2],
		    arp->ar_tha[3], arp->ar_tha[4], arp->ar_tha[5]);
		printf("	tpa=%s\n", inet_ntoa(arp->ar_tpa));
#endif

		logdb_appear(vlan, (struct ether_addr *)arp->ar_sha, AF_INET, &arp->ar_spa);

	} else {
		printf("unknown arp type\n");
		dumpstr((const char *)arp, pktlen);
	}

	return 0;
}

static int
recorder_ipv6_nd(struct ether_addr *dst, struct ether_addr *src, uint16_t type, int vlan, struct ip6icmp6nd *ip6icmpnd, int pktlen)
{
#if 0
	char buf1[128];
	char buf2[128];

	dump_eh(dst, src, type, vlan);

	switch (ip6icmpnd->nd_advert.nd_na_type) {
	case ND_ROUTER_SOLICIT:
		printf("ND_ROUTER_SOLICIT: %s -> %s\n",
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_dst, buf2, sizeof(buf2)));
		printf("	%s\n", inet_ntop(AF_INET6, &ip6icmpnd->nd_solicit.nd_ns_target, buf1, sizeof(buf1)));
		break;
	case ND_ROUTER_ADVERT:
		printf("ND_ROUTER_ADVERT: %s -> %s\n",
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_dst, buf2, sizeof(buf2)));
		printf("	%s\n", inet_ntop(AF_INET6, &ip6icmpnd->nd_advert.nd_na_target, buf1, sizeof(buf1)));
		break;
	case ND_NEIGHBOR_SOLICIT:
		printf("ND_NEIGHBOR_SOLICIT: %s -> %s\n",
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_dst, buf2, sizeof(buf2)));
		printf("	%s\n", inet_ntop(AF_INET6, &ip6icmpnd->nd_solicit.nd_ns_target, buf1, sizeof(buf1)));
		break;
	case ND_NEIGHBOR_ADVERT:
		printf("ND_NEIGHBOR_ADVERT: %s -> %s\n",
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_src, buf1, sizeof(buf1)),
		    inet_ntop(AF_INET6, &ip6icmpnd->ip6.ip6_dst, buf2, sizeof(buf2)));
		printf("	%s\n", inet_ntop(AF_INET6, &ip6icmpnd->nd_advert.nd_na_target, buf1, sizeof(buf1)));
		break;
	default:
		break;
	}
	dumpstr((const char *)ip6icmpnd, pktlen);
#endif

	logdb_appear(vlan, src, AF_INET6, &ip6icmpnd->ip6.ip6_src);

	return 0;
}

static int
recorder_unknown(struct ether_addr *dst, struct ether_addr *src, uint16_t type, int vlan, uint8_t *pkt, int pktlen)
{
	dump_eh(dst, src, type, vlan);
	dumpstr((const char *)pkt, pktlen);

	return 0;
}

void
packet_recorder(void *arg, unsigned char *pkt, int pktlen, const char *ifname)
{
	struct ether_header *eh;
	struct ether_vlan_header *evh;

	eh = (struct ether_header *)pkt;
	switch (ntohs(eh->ether_type)) {
	case ETHERTYPE_ARP:
		recorder_arp(
		    (struct ether_addr *)eh->ether_dhost,
		    (struct ether_addr *)eh->ether_shost,
		    ntohs(eh->ether_type), -1,
		    (struct arppkt *)(pkt + ETHER_HDR_LEN),
		    pktlen - ETHER_HDR_LEN);
		break;
	case ETHERTYPE_IPV6:
		recorder_ipv6_nd(
		    (struct ether_addr *)eh->ether_dhost,
		    (struct ether_addr *)eh->ether_shost,
		    ntohs(eh->ether_type), -1,
		    (struct ip6icmp6nd *)(pkt + ETHER_HDR_LEN),
		    pktlen - ETHER_HDR_LEN);
		break;
	case ETHERTYPE_VLAN:
		evh = (struct ether_vlan_header *)pkt;
		switch (ntohs(evh->evl_proto)) {
		case ETHERTYPE_ARP:
			recorder_arp(
			    (struct ether_addr *)evh->evl_dhost,
			    (struct ether_addr *)evh->evl_shost,
			    ntohs(evh->evl_proto),
			    EVL_VLANOFTAG(ntohs(evh->evl_tag)),
			    (struct arppkt *)(pkt + ETHER_HDR_LEN +
			    ETHER_VLAN_ENCAP_LEN),
			    pktlen - ETHER_HDR_LEN - ETHER_VLAN_ENCAP_LEN);
			break;
		case ETHERTYPE_IPV6:
			recorder_ipv6_nd(
			    (struct ether_addr *)evh->evl_dhost,
			    (struct ether_addr *)evh->evl_shost,
			    ntohs(evh->evl_proto),
			    EVL_VLANOFTAG(ntohs(evh->evl_tag)),
			    (struct ip6icmp6nd *)(pkt + ETHER_HDR_LEN +
			    ETHER_VLAN_ENCAP_LEN),
			    pktlen - ETHER_HDR_LEN - ETHER_VLAN_ENCAP_LEN);
			break;
		default:
			recorder_unknown(
			    (struct ether_addr *)evh->evl_dhost,
			    (struct ether_addr *)evh->evl_shost,
			    ntohs(evh->evl_proto),
			    EVL_VLANOFTAG(ntohs(evh->evl_tag)),
			    (pkt + ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN),
			    pktlen - ETHER_HDR_LEN - ETHER_VLAN_ENCAP_LEN);
			break;
		}
		break;
	default:
		recorder_unknown(
		    (struct ether_addr *)eh->ether_dhost,
		    (struct ether_addr *)eh->ether_shost,
		    ntohs(eh->ether_type), -1,
		    (pkt + ETHER_HDR_LEN),
		    pktlen - ETHER_HDR_LEN);
		break;
	}
}

static int
fdumpstr(FILE *fp, const char *data, size_t len)
{
	char ascii[17];
	size_t i;

	ascii[16] = '\0';
	for (i = 0; i < len; i++) {
		unsigned char c;

		if ((i & 15) == 0)
			fprintf(fp, "%08lx:", (unsigned long)i);

		c = *data++;
		fprintf(fp, " %02x", c);

		ascii[i & 15] = (0x20 <= c && c <= 0x7f) ? c : '.';

		if ((i & 15) == 15)
			fprintf(fp, " <%s>\n", ascii);
	}
	ascii[len & 15] = '\0';

	if (len & 15) {
		const char *white = "                                                ";
		fprintf(fp, "%s <%s>\n", &white[(len & 15) * 3], ascii);
	}

	return 0;
}

static int
dumpstr(const char *str, size_t len)
{
	return fdumpstr(stdout, str, len);
}
