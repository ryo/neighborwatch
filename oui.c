/*	$Id: oui.c,v 1.3 2014/01/02 22:22:19 ryo Exp $	*/

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>

#include "neighborwatch.h"
#include "oui.h"


struct oui {
	uint8_t oui[3];
	char vendor[128];
};

int oui_num;
struct oui *oui_table;

static int
parse_ethercodes(char *buf, struct oui *oui)
{
	/* parse "AB:CD:EF VENDORNAME" */
	oui->oui[0] = strtol(buf, &buf, 16);
	if (*buf++ != ':')
		return -1;
	oui->oui[1] = strtol(buf, &buf, 16);
	if (*buf++ != ':')
		return -1;
	oui->oui[2] = strtol(buf, &buf, 16);

	while (isspace(*buf & 0xff))
		buf++;

	strncpy(oui->vendor, buf, sizeof(oui->vendor));

	return 0;
}

int
ouicmp(const void *a, const void *b)
{
	return memcmp(((struct oui *)a)->oui, ((struct oui *)b)->oui,
	    sizeof(((struct oui *)a)->oui));
}

void
oui_reload(void)
{
	FILE *fp;
	char buf[256];
	int nalloc;
	char *p;
	int n;

	if (oui_table != NULL) {
		oui_num = 0;
		free(oui_table);
		oui_table = NULL;
	}

	fp = fopen(NEIGHBORWATCH_ETHERCODEDAT, "r");
	if (fp == NULL) {
		logging(LOG_WARNING, "open: %s: %s",
		    NEIGHBORWATCH_ETHERCODEDAT, strerror(errno));
		return;
	}

	nalloc = oui_num = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* chomp '\n' at end of line */
		n = strlen(buf);
		if ((n > 0) && (buf[n - 1] == '\n'))
			buf[n - 1] = '\0';

		/* skip comment */
		if (buf[0] == '#')
			continue;

		/* allocate oui_table */
		if (nalloc <= oui_num)
			nalloc += 512;
		p = realloc(oui_table, nalloc * sizeof(struct oui));
		if (p == NULL) {
			logging(LOG_WARNING,
			    "cannot allocate memory for reading %s\n",
			    NEIGHBORWATCH_ETHERCODEDAT);
			break;
		}
		oui_table = (struct oui *)p;

		if (parse_ethercodes(buf, &oui_table[oui_num]) != 0)
			continue;

		oui_num++;
	}

	qsort(oui_table, oui_num, sizeof(struct oui), ouicmp);
	fclose(fp);
}

const char *
oui_lookup(struct ether_addr *hwaddr)
{
	struct oui key, *oui;

	memset(&key, 0, sizeof(key));
	key.oui[0] = hwaddr->ether_addr_octet[0];
	key.oui[1] = hwaddr->ether_addr_octet[1];
	key.oui[2] = hwaddr->ether_addr_octet[2];

	oui = bsearch(&key, oui_table, oui_num, sizeof(struct oui), ouicmp);
	if (oui != NULL)
		return oui->vendor;
	return "unknown";
}
