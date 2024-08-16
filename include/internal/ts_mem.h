
#ifndef TINYSERVER_TS_MEM_H
#define TINYSERVER_TS_MEM_H

#include <stdio.h>
#include <sys/types.h>

void *ts__calloc(size_t nmemb, size_t size);
void ts__free(void *mem);
void *ts__malloc(size_t size);
#ifdef WITH_MEMORY_TRACKING
unsigned long ts__memory_used(void);
unsigned long ts__max_memory_used(void);
#endif
void *ts__realloc(void *ptr, size_t size);
char *ts__strdup(const char *s);

void ts__memory_set_limit(size_t lim);

#endif //TINYSERVER_TS_MEM_H
