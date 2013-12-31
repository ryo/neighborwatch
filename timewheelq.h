#ifndef _TIMEWHEELQ_H_
#define _TIMEWHEELQ_H_

#include <sys/queue.h>

#define TIMEWHEELQ_HEAD(name, type, ntable)				\
struct name {								\
	int twq_ntimetable;						\
	int twq_timeindexbase;						\
	LIST_HEAD(, type) twq_timetable[ntable];			\
}

#define TIMEWHEELQ_ENTRY(type)						\
	LIST_ENTRY(type)

#define TIMEWHEELQ_INIT(head, ntable) do {				\
	int i;								\
	(head)->twq_ntimetable = ntable;				\
	(head)->twq_timeindexbase = 0;					\
	for (i = 0; i < ntable; i++) {					\
		LIST_INIT(&((head)->twq_timetable[i]));			\
	}								\
} while (/*CONSTCOND*/0)

#define TIMEWHEELQ_INSERT_AFTER(listelm, elm, field)			\
	LIST_INSERT_AFTER(listelm, elm, field)

#define TIMEWHEELQ_INSERT_BEFORE(listelm, elm, field)			\
	LIST_INSERT_BEFORE(listelm, elm, field)

#define TIMEWHEELQ_INSERT_HEAD(head, nth_table, elm, field) do {	\
	int idx;							\
	idx = nth_table;						\
									\
	if (idx < 0)							\
		idx = 0;						\
	idx += (head)->twq_timeindexbase;				\
	idx %= (head)->twq_ntimetable;					\
									\
	LIST_INSERT_HEAD(&((head)->twq_timetable[idx]), elm, field);	\
} while (/*CONSTCOND*/0)

#define TIMEWHEELQ_CLEAR_ENTRY(elm, field)				\
	(((elm)->field.le_prev) = NULL)

#define TIMEWHEELQ_LINKED_ENTRY(elm, field)				\
	(((elm)->field.le_prev) != NULL)

#define TIMEWHEELQ_REMOVE(elm, field) do {				\
	LIST_REMOVE(elm, field);					\
	TIMEWHEELQ_CLEAR_ENTRY(elm, field);				\
} while (/*CONSTCOND*/0)

#define TIMEWHEELQ_EMPTY_TABLE(head, nth_table)				\
	LIST_EMPTY(&((head)->twq_timetable[((head)->twq_timeindexbase +	\
	     nth_table) % (head)->twq_ntimetable]))

#define TIMEWHEELQ_FIRST_TABLE(head, nth_table)				\
	LIST_FIRST(&((head)->twq_timetable[((head)->twq_timeindexbase +	\
	     nth_table) % (head)->twq_ntimetable]))

#define TIMEWHEELQ_NEXT(elm, field)					\
	LIST_NEXT(elm, field)

#define TIMEWHEELQ_FOREACH_TABLE(var_n, var_elem, head, field)		\
	for (var_n = 0; var_n < (head)->twq_ntimetable; var_n++)	\
		LIST_FOREACH(var_elem,					\
		    &((head)->twq_timetable[((head)->twq_timeindexbase +\
		    var_n) % (head)->twq_ntimetable]), field)

#define TIMEWHEELQ_ROTATE(head) do {					\
	(head)->twq_timeindexbase =					\
	    ((head)->twq_timeindexbase + 1) % (head)->twq_ntimetable;	\
} while (/*CONSTCOND*/0)

#define TIMEWHEELQ_DEBUG(head, type, field) do {			\
	int i;								\
	printf("[%p]\n", head);						\
	printf(" twq_ntimetable = %d\n", (head)->twq_ntimetable);	\
	printf(" twq_timeindexbase = %d\n", (head)->twq_timeindexbase);	\
	for (i = 0; i < (head)->twq_ntimetable; i++) {			\
		struct type *p;						\
		int idx = ((head)->twq_timeindexbase + i) %		\
		    (head)->twq_ntimetable;				\
									\
		if (LIST_FIRST(&((head)->twq_timetable[idx]))) {	\
			printf(" twq_timetable[%d]:", idx);		\
			LIST_FOREACH(p, &((head)->twq_timetable[idx]),	\
			    field) {					\
				printf("<%p>", p);			\
			}						\
			printf("\n");					\
		}							\
	}								\
} while (/*CONSTCOND*/0)

#endif /* _TIMEWHEELQ_H_ */
