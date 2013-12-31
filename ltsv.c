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
#include <string.h>
#include "ltsv.h"

int
ltsv_open(struct ltsv *ltsv, const char *file)
{
	memset(ltsv, 0, sizeof(*ltsv));

#ifndef LTSV_FIXED_LENGTH
#define LTSV_ALLOC_LENGTH	64
#define LTSV_ALLOC_BLOCK	256
	ltsv->_key.str = malloc(LTSV_ALLOC_LENGTH);
	if (ltsv->_key.str == NULL)
		return -1;
	ltsv->_value.str = malloc(LTSV_ALLOC_LENGTH);
	if (ltsv->_value.str == NULL) {
		free(ltsv->_key.str);
		ltsv->_key.str = NULL;
		return -1;
	}
	ltsv->_key.alloc = LTSV_ALLOC_LENGTH;
	ltsv->_value.alloc = LTSV_ALLOC_LENGTH;
#endif

	if ((ltsv->fp = fopen(file, "r")) == NULL)
		return -1;
	ltsv->_flags |= LTSV_FLAGS_OPENED;
	return 0;
}

int
ltsv_close(struct ltsv *ltsv)
{
	if (ltsv->_flags & LTSV_FLAGS_OPENED)
		fclose(ltsv->fp);
	ltsv->_flags &= ~LTSV_FLAGS_OPENED;
#ifndef LTSV_FIXED_LENGTH
	if (ltsv->_key.str != NULL) {
		free(ltsv->_key.str);
		ltsv->_key.str = NULL;
	}
	if (ltsv->_value.str != NULL) {
		free(ltsv->_value.str);
		ltsv->_value.str = NULL;
	}
#endif
	return 0;
}

int
ltsv_get(struct ltsv *ltsv)
{
	int n;
	int c;
	char *p;
	int done;
	size_t lim;

	if (ltsv->_flags & LTSV_FLAGS_EOF)
		return -1;

	if (ltsv->_flags & LTSV_FLAGS_EOL) {
		ltsv->column = 0;
		ltsv->line++;
		ltsv->_flags &= ~LTSV_FLAGS_EOL;
	} else if (!(ltsv->_flags & LTSV_FLAGS_INITTED)) {
		ltsv->column = 0;
		ltsv->line = 1;
		ltsv->_flags |= LTSV_FLAGS_INITTED;
	} else {
		ltsv->column++;
	}

	ltsv->_key.str[0] = '\0';
	ltsv->_value.str[0] = '\0';

#ifdef LTSV_FIXED_LENGTH
	lim = sizeof(ltsv->_key.str);
#else
	lim = ltsv->_key.alloc;
#endif
	p = ltsv->_key.str;
	n = 0;
	for (done = 0; done == 0;) {
		c = fgetc(ltsv->fp);
		switch (c) {
		case EOF:
			*p = '\0';
			ltsv->_flags |= LTSV_FLAGS_EOF;
			if (n == 0)
				return -1;
			return 0;
		case '\n':
			*p = '\0';
			ltsv->_flags |= LTSV_FLAGS_EOL;
			return 0;
		case ':':
			*p = '\0';
			done = 1;
			break;
		default:
#ifndef LTSV_FIXED_LENGTH
			if ((n + 1) >= lim) {
				size_t off;
				char *newbuf;

				off = p - ltsv->_key.str;
				if (ltsv->_key.alloc >= LTSV_ALLOC_BLOCK)
					ltsv->_key.alloc += LTSV_ALLOC_BLOCK;
				else
					ltsv->_key.alloc *= 2;
				newbuf = realloc(ltsv->_key.str, ltsv->_key.alloc);
				lim = ltsv->_key.alloc;
				ltsv->_key.str = newbuf;
				p = ltsv->_key.str + off;
			}
			*p++ = c;
#else
			if ((n + 1) < lim)
				*p++ = c;
#endif
			n++;
		}
	}

#ifdef LTSV_FIXED_LENGTH
	lim = sizeof(ltsv->_value.str);
#else
	lim = ltsv->_value.alloc;
#endif
	p = ltsv->_value.str;
	n = 0;
	for (done = 0; done == 0;) {
		c = fgetc(ltsv->fp);
		switch (c) {
		case EOF:
			*p = '\0';
			ltsv->_flags |= LTSV_FLAGS_EOF;
			done = 1;
			break;
		case '\n':
			*p = '\0';
			ltsv->_flags |= LTSV_FLAGS_EOL;
			done = 1;
			break;
		case '\t':
			*p = '\0';
			done = 1;
			break;
		default:
#ifndef LTSV_FIXED_LENGTH
			if ((n + 1) >= lim) {
				size_t off;
				char *newbuf;

				off = p - ltsv->_value.str;
				if (ltsv->_value.alloc >= LTSV_ALLOC_BLOCK)
					ltsv->_value.alloc += LTSV_ALLOC_BLOCK;
				else
					ltsv->_value.alloc *= 2;
				newbuf = realloc(ltsv->_value.str, ltsv->_value.alloc);
				lim = ltsv->_value.alloc;
				ltsv->_value.str = newbuf;
				p = ltsv->_value.str + off;
			}
			*p++ = c;
#else
			if ((n + 1) < lim)
				*p++ = c;
#endif
			n++;
		}
	}

	return 0;
}
