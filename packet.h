/*	$Id: packet.h,v 1.5 2013/12/23 15:33:12 ryo Exp $	*/

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

#ifndef _PACKET_H_
#define _PACKET_H_

/* ethernet arp packet */
struct arppkt {
	uint16_t ar_hrd;			/* +0x00 */
	uint16_t ar_pro;			/* +0x02 */
	uint8_t ar_hln;				/* +0x04 */
	uint8_t ar_pln;				/* +0x05 */
	uint16_t ar_op;				/* +0x06 */
	uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
	struct in_addr ar_spa;			/* +0x0e */
	uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
	struct in_addr ar_tpa;			/* +0x18 */
						/* +0x1c */
};

struct ip6icmp6nd {
	struct ip6_hdr ip6;
	union {
		struct nd_neighbor_solicit nd_solicit;
		struct nd_neighbor_advert nd_advert;
	} ip6icmp6nd;
#define nd_solicit	ip6icmp6nd.nd_solicit
#define nd_advert	ip6icmp6nd.nd_advert
};

#endif /* _PACKET_H_ */
