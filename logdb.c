/*	$Id: logdb.c,v 1.26 2014/01/02 22:30:00 ryo Exp $	*/

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
#include <sys/tree.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "neighborwatch.h"
#include "oui.h"
#include "logdb.h"
#include "timewheelq.h"
#include "ltsv.h"

#define DATA_EXPIRE_SECOND	(60 * 60 * 24)	/* 1 days */

struct addr {
	struct {
		int af;
		int vlan;
		union {
			struct in_addr addr4;
			struct in6_addr addr6;
		} addr;
	} key;

	struct data *parent;
	time_t lastseen;
	TIMEWHEELQ_ENTRY(addr) timetable;
	LIST_ENTRY(addr) list;
};

struct data {
	struct {
		struct ether_addr eaddr;
	} key;

	time_t appearance_time;
	time_t disappearance_time;
#ifdef DETECT_OS_AND_USER
	char user[64];
	char os[64];
#endif

	RB_ENTRY(data) tree;
	LIST_HEAD(, addr) addrlist;
};

static void logaddr(const char *, struct data *, struct addr *);
static void logether(const char *, struct data *);

RB_HEAD(logdb, data) logdb_tree_head;

#define MAXTABLE	2048
TIMEWHEELQ_HEAD(, addr, MAXTABLE) timewheel_addr_head;

struct timespec monotonic_now;
struct timespec realtime_now;
static int logdb_logging = 0;
static int data_expire_second = DATA_EXPIRE_SECOND;

void
logdb_log_enable(int on)
{
	logdb_logging = on;
}


static char *
strmacaddr(struct ether_addr *eaddr)
{
	static char buf[32];

	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
	    eaddr->ether_addr_octet[0], eaddr->ether_addr_octet[1],
	    eaddr->ether_addr_octet[2], eaddr->ether_addr_octet[3],
	    eaddr->ether_addr_octet[4], eaddr->ether_addr_octet[5]);

	return buf;
}

struct addr *
addr_new(void)
{
	struct addr *addr;

	addr = malloc(sizeof(struct addr));
	if (addr != NULL) {
		memset(addr, 0, sizeof(*addr));
	}
	return addr;
}

static void
dump_addr(struct addr *addr, int dispsec)
{
	char buf[128];
	struct hostent *hp;

	if (addr->key.vlan >= 0)
		printf("VLAN%4d ", addr->key.vlan);
	else
		printf("         ");

	switch (addr->key.af) {
	case AF_INET:
		printf("%s ", inet_ntop(AF_INET, &addr->key.addr.addr4, buf,
		    sizeof(buf)));
		hp = gethostbyaddr((char *)&addr->key.addr.addr4,
		    sizeof(addr->key.addr.addr4), AF_INET);
		if (hp != NULL)
			printf("(%s) ", hp->h_name);
		break;
	case AF_INET6:
		printf("%s ", inet_ntop(AF_INET6, &addr->key.addr.addr6, buf,
		    sizeof(buf)));
		hp = gethostbyaddr((char *)&addr->key.addr.addr6,
		    sizeof(addr->key.addr.addr6), AF_INET6);
		if (hp != NULL)
			printf("(%s) ", hp->h_name);
		break;
	}
	if (dispsec) {
		printf("(%lld sec ago)",
		    (long long)(monotonic_now.tv_sec - addr->lastseen));
	}
	printf("\n");
}

void
addr_delete(struct addr *addr)
{
	logaddr("disappear", addr->parent, addr);

	TIMEWHEELQ_REMOVE(addr, timetable);
	LIST_REMOVE(addr, list);

	free(addr);
}

static char *
timestamp(time_t t)
{
	static char tstamp[128];
	time_t mytime;
	struct tm ltime;

	mytime = t;
	localtime_r(&mytime, &ltime);
	strftime(tstamp, sizeof(tstamp), "%F %T", &ltime);

	return tstamp;
}

static void
dump_data(struct data *data)
{
	struct addr *addr;
	int i;

	printf("%s ",
	    strmacaddr(&data->key.eaddr));

	printf("%s ", timestamp(data->appearance_time));
	if (data->disappearance_time != 0)
		printf("%s ", timestamp(data->disappearance_time));
	else
		printf("-                   ");

	i = 0;
	LIST_FOREACH(addr, &data->addrlist, list) {
		if (i == 0)
			i++;
		else
			printf("                                                          ");

		dump_addr(addr, 1);
	}
	if (i == 0)
		printf("\n");
}

static inline int
logdb_datacmp(struct data *a, struct data *b)
{
	return memcmp(a->key.eaddr.ether_addr_octet,
	    b->key.eaddr.ether_addr_octet,
	    sizeof(a->key.eaddr.ether_addr_octet));
}

RB_PROTOTYPE(logdb, data, tree, logdb_datacmp);
RB_GENERATE(logdb, data, tree, logdb_datacmp);

static void
timewheel_reset(struct data *data, struct addr *addr)
{
	TIMEWHEELQ_REMOVE(addr, timetable);
	TIMEWHEELQ_INSERT_HEAD(&timewheel_addr_head,
	    addr->lastseen + DATA_EXPIRE_SECOND - monotonic_now.tv_sec,
	    addr, timetable);
	LIST_REMOVE(addr, list);
	LIST_INSERT_HEAD(&data->addrlist, addr, list);
}

static struct addr *
data_update(struct data *data, int vlan, int af, void *address)
{
	struct addr k;
	struct addr *addr;
	int found = 0;

	memset(&k, 0, sizeof(k));
	k.key.af = af;
	k.key.vlan = vlan;
	switch (af) {
	case AF_INET:
		k.key.addr.addr4 = *(struct in_addr *)address;
		break;
	case AF_INET6:
		k.key.addr.addr6 = *(struct in6_addr *)address;
		break;
	}

	data->disappearance_time = 0;

	LIST_FOREACH(addr, &data->addrlist, list) {
		if (memcmp(&addr->key, &k.key, sizeof(addr->key)) == 0) {
			found = 1;
			addr->lastseen = monotonic_now.tv_sec;
			timewheel_reset(data, addr);
			break;
		}
	}

	if (found == 0) {
		addr = addr_new();
		memcpy(&addr->key, &k.key, sizeof(addr->key));
		addr->lastseen = monotonic_now.tv_sec;
		TIMEWHEELQ_INSERT_HEAD(&timewheel_addr_head,
		    DATA_EXPIRE_SECOND, addr, timetable);
		LIST_INSERT_HEAD(&data->addrlist, addr, list);
		addr->parent = data;

		logaddr("appear", data, addr);
	}

	return addr;
}

static struct data *
data_new(struct ether_addr *hwaddr)
{
	struct data *data;

	data = malloc(sizeof(*data));
	if (data != NULL) {
		memset(data, 0, sizeof(*data));

		memcpy(data->key.eaddr.ether_addr_octet, hwaddr,
		    ETHER_ADDR_LEN);
		data->appearance_time = realtime_now.tv_sec;

		RB_INSERT(logdb, &logdb_tree_head, data);
	}
	return data;
}

#ifdef FORGET_HWADDR
static int
data_delete(struct data *data)
{
	RB_REMOVE(logdb, &logdb_tree_head, data);
	free(data);
	return 0;
}
#else
static int
data_dropoff(struct data *data)
{
	data->disappearance_time = realtime_now.tv_sec - DATA_EXPIRE_SECOND;
	return 0;
}
#endif

static int
data_expire_check(void)
{
	struct data *data;
	struct addr *addr, *next;
	time_t left;

	for (addr = TIMEWHEELQ_FIRST_TABLE(&timewheel_addr_head, 0);
	    addr != NULL; addr = next) {
		next = TIMEWHEELQ_NEXT(addr, timetable);
		left = addr->lastseen + DATA_EXPIRE_SECOND -
		    monotonic_now.tv_sec;
		if (left <= 0) {
			data = addr->parent;
			addr_delete(addr);
			if (LIST_EMPTY(&data->addrlist)) {
#ifdef FORGET_HWADDR
				data_delete(data);
#else
				data_dropoff(data);
#endif
			}
		}
	}

	return 0;
}

int
logdb_init(int expiretime)
{
	if (expiretime)
		data_expire_second = expiretime;

	TIMEWHEELQ_INIT(&timewheel_addr_head, MAXTABLE);
	RB_INIT(&logdb_tree_head);
	return 0;
}

int
logdb_appear(int vlan, struct ether_addr *hwaddr, int af, void *address)
{
	struct data *data;
	struct data key;

	memset(&key, 0, sizeof(key));
	memcpy(key.key.eaddr.ether_addr_octet, hwaddr, ETHER_ADDR_LEN);

	data = RB_FIND(logdb, &logdb_tree_head, &key);

	if (data != NULL) {
		data_update(data, vlan, af, address);
	} else {
		data = data_new(hwaddr);
		logether("new station", data);
		data_update(data, vlan, af, address);
	}
	return 0;
}


/* called once per second */
int
logdb_clock(int force)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (!force && (now.tv_sec == monotonic_now.tv_sec))
		return -1;

	monotonic_now = now;
	clock_gettime(CLOCK_REALTIME, &realtime_now);
	data_expire_check();
	TIMEWHEELQ_ROTATE(&timewheel_addr_head);
	return 0;
}

time_t
logdb_monotonic2realtime(time_t t)
{
	time_t dif;

	dif = realtime_now.tv_sec - monotonic_now.tv_sec;
	return t + dif;
}

time_t
logdb_realtime2monotonic(time_t t)
{
	time_t dif;

	dif = realtime_now.tv_sec - monotonic_now.tv_sec;
	return t - dif;
}

void
logdb_dump(void)
{
	struct data *data;

	RB_FOREACH(data, logdb, &logdb_tree_head) {
		dump_data(data);
	}
}

void
logether(const char *msg, struct data *data)
{
	logging(LOG_INFO, "%s %s (%s)", msg, strmacaddr(&data->key.eaddr),
	    oui_lookup(&data->key.eaddr));
}

void
logaddr(const char *msg, struct data *data, struct addr *addr)
{
#if defined(NEIGHBORWATCH_MACDBDIR) || defined(NEIGHBORWATCH_LOGFILE)
	char filepath[MAXPATHLEN];
	FILE *fp;
#endif
	char buf[128];
	char logbuf[1024];
	int len, loglen;
	char *tstamp;
	char *p;
	struct hostent *hp;

	if (!logdb_logging)
		return;

	tstamp = timestamp(realtime_now.tv_sec);

	loglen = sizeof(logbuf);
	p = logbuf;

	len = snprintf(p, loglen, "%s: %s ", msg, strmacaddr(&data->key.eaddr));
	loglen -= len;
	p += len;

	if (addr->key.vlan >= 0) {
		len = snprintf(p, loglen, "VLAN %d: ", addr->key.vlan);
		loglen -= len;
		p += len;
	}

	switch (addr->key.af) {
	case AF_INET:
		len = snprintf(p, loglen, "%s", inet_ntop(AF_INET,
		    &addr->key.addr.addr4, buf, sizeof(buf)));
		loglen -= len;
		p += len;
		hp = gethostbyaddr((char *)&addr->key.addr.addr4,
		    sizeof(addr->key.addr.addr4), AF_INET);
		len = snprintf(p, loglen, " %s", hp == NULL ? "-" : hp->h_name);
		loglen -= len;
		p += len;
		break;
	case AF_INET6:
		len = snprintf(p, loglen, "%s", inet_ntop(AF_INET6,
		    &addr->key.addr.addr6, buf, sizeof(buf)));
		loglen -= len;
		p += len;
		hp = gethostbyaddr((char *)&addr->key.addr.addr6,
		    sizeof(addr->key.addr.addr6), AF_INET6);
		len = snprintf(p, loglen, " %s", hp == NULL ? "-" : hp->h_name);
		loglen -= len;
		p += len;
		break;
	}

	len = snprintf(p, loglen, " (%s)", oui_lookup(&data->key.eaddr));

#ifdef NEIGHBORWATCH_MACDBDIR
	snprintf(filepath, sizeof(filepath), "%s/%s", NEIGHBORWATCH_MACDBDIR,
	    strmacaddr(&data->key.eaddr));
	fp = fopen(filepath, "aw");
	if (fp != NULL) {
		fprintf(fp, "%s %s\n", tstamp, logbuf);
		fclose(fp);
	}
#endif

#ifdef NEIGHBORWATCH_LOGFILE
	fp = fopen(NEIGHBORWATCH_LOGFILE, "aw");
	if (fp != NULL) {
		fprintf(fp, "%s %s\n", tstamp, logbuf);
		fclose(fp);
	}
#endif

	logging(LOG_INFO, "%s", logbuf);
}

int
dat_save(time_t next_interval)
{
	static time_t lastsave = 0;
	char addrbuf[128];
	char vlanbuf[16];
	FILE *fp;
	struct data *data;
	struct addr *addr;

	if ((lastsave != 0) && (lastsave + next_interval) > monotonic_now.tv_sec)
		return -1;
	lastsave = monotonic_now.tv_sec;

	fp = fopen(NEIGHBORWATCH_DATFILE, "w");
	if (fp == NULL)
		return -1;

	RB_FOREACH(data, logdb, &logdb_tree_head) {
		fprintf(fp, "hwaddr:%s", strmacaddr(&data->key.eaddr));

		fprintf(fp, "	appearancetime:%llu",
		    (unsigned long long)data->appearance_time);
		fprintf(fp, "	disappearancetime:%llu",
		    (unsigned long long)data->disappearance_time);

#ifdef DETECT_OS_AND_USER
		fprintf(fp, "	user:%s"
		    data->user[0] == '\0' ? "-" : data->user,
		fprintf(fp, "	os:%s",
		    data->os[0] == '\0' ? "-" : data->os);
#endif

		LIST_FOREACH(addr, &data->addrlist, list) {
			if (addr->key.vlan >= 0)
				snprintf(vlanbuf, sizeof(vlanbuf), "vlan%d,", addr->key.vlan);
			else
				vlanbuf[0] = '\0';

			switch (addr->key.af) {
			case AF_INET:
				fprintf(fp, "	inet:%s%s,%llu",
				    vlanbuf,
				    inet_ntop(AF_INET, &addr->key.addr.addr4,
				    addrbuf, sizeof(addrbuf)),
				    (unsigned long long)
				    logdb_monotonic2realtime(addr->lastseen));
				break;
			case AF_INET6:
				fprintf(fp, "	inet6:%s%s,%llu",
				    vlanbuf,
				    inet_ntop(AF_INET6, &addr->key.addr.addr6,
				    addrbuf, sizeof(addrbuf)),
				    (unsigned long long)
				    logdb_monotonic2realtime(addr->lastseen));
				break;
			}
		}
		fprintf(fp, "\n");
	}

	fclose(fp);

	return 0;
}

int
dat_restore(void)
{
	struct ltsv ltsv;
	int rc, vlan, af;
	struct ether_addr *eaddr;
	struct data *data = NULL;
	struct addr *addr = NULL;
	char *p, *q;
	struct in_addr in;
	struct in6_addr in6;
	time_t t;

	rc = ltsv_open(&ltsv, NEIGHBORWATCH_DATFILE);
	if (rc != 0)
		return -1;

	while (ltsv_get(&ltsv) == 0) {
		if ((strcmp(LTSV_KEY(&ltsv), "hwaddr") == 0) &&
		    ((eaddr = ether_aton(LTSV_VALUE(&ltsv))) != NULL)) {
			data = data_new(eaddr);
		}

		if (strcmp(LTSV_KEY(&ltsv), "appearancetime") == 0) {
			if (data != NULL)
				data->appearance_time = strtoll(LTSV_VALUE(&ltsv), NULL, 10);
		}
		if (strcmp(LTSV_KEY(&ltsv), "disappearancetime") == 0) {
			if (data != NULL)
				data->disappearance_time = strtoll(LTSV_VALUE(&ltsv), NULL, 10);
		}

		af = -1;
		if (strcmp(LTSV_KEY(&ltsv), "inet") == 0)
			af = AF_INET;
		else if (strcmp(LTSV_KEY(&ltsv), "inet6") == 0)
			af = AF_INET6;
		if (af != -1) {
			p = LTSV_VALUE(&ltsv);
			if (strncmp("vlan", p, 4) == 0) {
				vlan = strtol(p + 4, &p, 10);
				p += 1;
			} else {
				vlan = -1;
			}
			q = p;
			while ((*q != ',') && (*q != '\0'))
				q++;
			if (*q == '\0')
				continue;
			*q++ = '\0';

			switch (af) {
			case AF_INET:
				inet_pton(AF_INET, p, &in);
				addr = data_update(data, vlan, af, &in);
				break;
			case AF_INET6:
				inet_pton(AF_INET6, p, &in6);
				addr = data_update(data, vlan, af, &in6);
				break;
			}

			t = strtoll(q, NULL, 10);
			addr->lastseen = logdb_realtime2monotonic(t);
			timewheel_reset(data, addr);
		}
	}

	return 0;
}
