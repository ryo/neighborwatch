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
#ifndef _LTSV_H_
#define _LTSV_H_

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#if 0
#define LTSV_FIXED_LENGTH	64	/* if defined: no malloc mode (for embedded use) */
#endif

struct ltsv {
	FILE *fp;
	int column;
	int line;
	uint32_t _flags;
#define LTSV_FLAGS_OPENED	0x00000001
#define LTSV_FLAGS_INITTED	0x00000002
#define LTSV_FLAGS_EOL		0x00000004
#define LTSV_FLAGS_EOF		0x00000008
	struct {
#ifdef LTSV_FIXED_LENGTH
		char str[LTSV_FIXED_LENGTH];
#else
		size_t alloc;
		char *str;
#endif
	} _key, _value;
};

#define LTSV_LINE(ltsv)		(ltsv)->line
#define LTSV_COLUMN(ltsv)	(ltsv)->column
#define LTSV_KEY(ltsv)		(ltsv)->_key.str
#define LTSV_VALUE(ltsv)	(ltsv)->_value.str

int ltsv_open(struct ltsv *, const char *);
int ltsv_close(struct ltsv *);
int ltsv_get(struct ltsv *);

#endif /* _LTSV_H_ */
