/*	$Id: neighborwatch.c,v 1.24 2014/01/06 05:19:44 ryo Exp $	*/

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
#include <sys/types.h>
#include <sys/stdint.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#ifdef __FreeBSD__
#include <libutil.h>
#else
#include <util.h>
#endif

#include "neighborwatch.h"
#include "neighborwatch_bpf.h"
#include "logdb.h"
#include "oui.h"

struct iflist_item {
	TAILQ_ENTRY(iflist_item) list;
	int fd;
	char ifname[IF_NAMESIZE + 1];
};

TAILQ_HEAD(iflist_head, iflist_item);

int main(int, char *[]);
static void usage(void);
static int neighborwatch_main(int, char *[]);

struct iflist_item *iflist_append(struct iflist_head *, char *);
struct iflist_item *iflist_exists(struct iflist_head *, char *);
int iflist_move(struct iflist_head *, struct iflist_head *, struct iflist_item *);
int iflist_delete(struct iflist_head *, struct iflist_item *);
int iflist_deleteall(struct iflist_head *);
int iflist_count(struct iflist_head *);
static void sighandler(int);

struct iflist_head iflist = TAILQ_HEAD_INITIALIZER(iflist);

pid_t pid;
int neighborwatch_debug;
int verbose;
int promisc = 1;
int sighup;
int siginfo;
int sigterm;
int datsave_interval = 15 * 60;	/* second */
int logging_opened;

unsigned int pktbufsize = PKTBUFSIZE;
unsigned char pktbuf[PKTBUFSIZE];


static void
usage(void)
{
	fprintf(stderr, "usage: neighborwatch [options] [interface [...]]\n");
	fprintf(stderr, "	-p		Don't put the interface into promiscuous mode\n");
	fprintf(stderr, "	-v		verbose\n");
	fprintf(stderr, "	-d		Run in debug mode, with all the output to stderr,\n");
	fprintf(stderr, "			and will not detach and does not become a daemon.\n");
	fprintf(stderr, "	-i [seconds]	specify interval of dat save (default:900\n");
	fprintf(stderr, "	-e [seconds]	specify time of address expire (default:86400)\n");
}

void
logging_start(void)
{
	openlog("neighborwatch", LOG_PID|LOG_NDELAY, LOG_DAEMON);
	logging_opened = 1;
}

void
logging_end(void)
{
	if (logging_opened)
		closelog();
}

void
logging(int prio, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (neighborwatch_debug || !logging_opened) {
		vfprintf(stderr, fmt, ap);
		printf("\n");
	} else {
		vsyslog(prio, fmt, ap);
	}
	va_end(ap);
}

struct iflist_item *
iflist_append(struct iflist_head *head, char *str)
{
	size_t len;
	struct iflist_item *elm;

	/* already exists? */
	if ((elm = iflist_exists(head, str)) != NULL)
		return elm;

	len = strlen(str);
	if (len == 0)
		return NULL;

	elm = malloc(sizeof(struct iflist_item));
	if (elm == NULL)
		return NULL;

	memset(elm, 0, sizeof(*elm));
	strncpy(elm->ifname, str, IFNAMSIZ);
	TAILQ_INSERT_HEAD(head, elm, list);

	return elm;
}

struct iflist_item *
iflist_exists(struct iflist_head *head, char *str)
{
	struct iflist_item *elm;

	TAILQ_FOREACH(elm, head, list) {
		if (strcmp(elm->ifname, str) == 0)
			return elm;
	}
	return NULL;
}

int
iflist_count(struct iflist_head *head)
{
	int n;
	struct iflist_item *elm;

	n = 0;
	TAILQ_FOREACH(elm, head, list) {
		n++;
	}

	return n;
}

int
iflist_move(struct iflist_head *head1, struct iflist_head *head2, struct iflist_item *elm)
{
	TAILQ_REMOVE(head1, elm, list);
	if (iflist_exists(head2, elm->ifname) == NULL)
		TAILQ_INSERT_HEAD(head2, elm, list);

	return 0;
}

int
iflist_delete(struct iflist_head *head, struct iflist_item *elm)
{
	TAILQ_REMOVE(head, elm, list);
	free(elm);

	return 0;
}

int
iflist_deleteall(struct iflist_head *head)
{
	struct iflist_item *elm;
	while ((elm = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, elm, list);
		free(elm);
	}
	return 0;
}

static int
neighborwatch_main(int argc, char *argv[])
{
	static const struct timespec tout = { 1, 0 };	/* 1sec */
#define MAX_IFNUM	128
	struct kevent kev[MAX_IFNUM];
	struct kevent ev[MAX_IFNUM];
	struct iflist_item *ifitem, *ifitem_next;
	int i, kq, nev, nfd, ret, kevent_errno;
	ssize_t rc;

	ret = -1;
	kq = -1;

	/*
	 * initialize kevent structure and setup
	 */
	memset(kev, 0, sizeof(kev));
	nfd = 0;

	/* open interfaces, and setup kevent structure */
	if (iflist_count(&iflist) > MAX_IFNUM) {
		logging(LOG_ERR, "too many interfaces");
		goto neighborwatch_done;
	}

	/* add arguments to interfaces list */
	for (i = 0; i < argc; i++)
		iflist_append(&iflist, argv[i]);

	/* setup interfaces */
	TAILQ_FOREACH_SAFE(ifitem, &iflist, list, ifitem_next) {
		if ((ifitem->fd = neighborwatch_open(ifitem->ifname, promisc,
		    &pktbufsize, 1)) < 0) {
			iflist_delete(&iflist, ifitem);
			continue;
		}

		EV_SET(&kev[nfd], ifitem->fd, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0,
#ifdef __NetBSD__
		    (uintptr_t)ifitem
#else
		    (void *)ifitem
#endif
		);
		nfd++;
	}

	/* exists any valid interface? */
	if (iflist_count(&iflist) == 0) {
		logging(LOG_ERR, "no listening interface");
		goto neighborwatch_done;
	}

	/*
	 * set kqueue
	 */
	if ((kq = kqueue()) == -1) {
		logging(LOG_ERR, "kqueue: %s", strerror(errno));
		goto neighborwatch_done;
	}
	if (kevent(kq, kev, nfd, NULL, 0, NULL) == -1) {
		logging(LOG_ERR, "kevent: %s", strerror(errno));
		goto neighborwatch_done;
	}

	TAILQ_FOREACH(ifitem, &iflist, list)
		logging(LOG_DEBUG, "listening on %s", ifitem->ifname);

	/*
	 * daemon loop
	 */
	for (ret = 0;;) {
		if (sighup || sigterm)
			goto neighborwatch_done;

		if (siginfo) {
			if (neighborwatch_debug) {
				TAILQ_FOREACH(ifitem, &iflist, list)
					logging(LOG_DEBUG, "listening on %s (fd=%d)", ifitem->ifname, ifitem->fd);
				logdb_dump();
			}

			siginfo = 0;
		}

		nev = kevent(kq, NULL, 0, ev, nfd, &tout);
		kevent_errno = errno;
		logdb_clock(0);
		dat_save(datsave_interval);
		if (nev == -1) {
			if (kevent_errno == EINTR)
				continue;
			logging(LOG_ERR, "kevent: %s", strerror(kevent_errno));
			goto neighborwatch_done;
		} else if (nev == 0) {
			/* timeout */
			continue;
		}

		for (i = 0; i < nev; i++) {
			ifitem = (struct iflist_item *)ev[i].udata;

			rc = pktread_and_exec(packet_recorder, NULL,
			     ifitem->fd, ifitem->ifname,
			     pktbuf, pktbufsize);
		}
	}

 neighborwatch_done:
	if (kq > 0)
		close(kq);
	for (i = 0; i < nfd; i++) {
		ifitem = (struct iflist_item *)kev[i].udata;

		if (neighborwatch_debug)
			logging(LOG_DEBUG, "close: %d", ifitem->fd);
		neighborwatch_close(ifitem->fd);
	}
	return ret;
}

static void
sighandler(int signo)
{
	switch (signo) {
	case SIGHUP:
		sighup = 1;
		break;
	case SIGINFO:
		siginfo = 1;
		break;
	case SIGTERM:
		sigterm = 1;
		break;
	default:
		break;
	}
}

int
main(int argc, char *argv[])
{
	struct sigaction sa;
	int ch, expiretime, rc;

	expiretime = 0;
	while ((ch = getopt(argc, argv, "D:deipv")) != -1) {
		switch (ch) {
		case 'd':
			neighborwatch_debug = 1;
			break;
		case 'e':
			expiretime = strtol(optarg, NULL, 10);
			break;
		case 'i':
			datsave_interval = strtol(optarg, NULL, 10);
			break;
		case 'p':
			promisc = 0;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;


	if (argc == 0) {
		usage();
		return 1;
	}

	if (!neighborwatch_debug) {
#ifdef __FreeBSD__
		pid_t pid;
		struct pidfh *pfh;

		if ((pfh = pidfile_open(PATH_NEIGHBORWATCH_PID, 0600, &pid)) == NULL) {
			if (errno == EEXIST) {
				syslog(LOG_ERR, "%s already running, pid %d",
				       getprogname(), (int)pid);
				return 2;
			}
			logging(LOG_WARNING, "pidfile_open: %s", strerror(errno));
			return 2;
		}
#endif
		rc = daemon(0, 0);
		if (rc < 0) {
			fprintf(stderr, "daemon: %s", strerror(errno));
			return 3;
		}
#ifdef __FreeBSD__
		if (pfh != NULL && pidfile_write(pfh) == -1) {
			logging(LOG_WARNING, "pidfile_write: %s", strerror(errno));
			return 4;
		}
#else
		if (pidfile(PATH_NEIGHBORWATCH_PID) != 0) {
			logging(LOG_ERR, "failed to write a pid file: %s", PATH_NEIGHBORWATCH_PID);
			return 4;
		}
#endif

		logging_start();
	}

	/*
	 * setup signal handlers
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sighandler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINFO, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	logdb_init(expiretime);
	oui_reload();	/* load "ethercodes.dat" */

	logdb_clock(0);	/* for initialize timer */
	dat_restore();	/* load entries from "neighborwatch.dat" */
	logdb_clock(1);	/* expire old entries (no logging) */
	logdb_log_enable(1);

	for (;;) {
		rc = neighborwatch_main(argc, argv);	/* would return if any signals */
		if (rc != 0)
			break;

		if (sigterm) {
			dat_save(0);
			sigterm = 0;
			break;
		}

		if (sighup) {
			oui_reload();	/* load "ethercodes.dat" */
			logging(LOG_INFO, "reload %s", NEIGHBORWATCH_ETHERCODEDAT);
			dat_save(0);
			sighup = 0;
		}
	}

	logging(LOG_INFO, "terminated");
	closelog();

	return 0;
}
