
#include <stdlib.h>
#include <string.h>

#include "internal/ts_mem.h"

#ifdef WITH_MEMORY_TRACKING
#  if defined(__APPLE__)
#    include <malloc/malloc.h>
#    define malloc_usable_size malloc_size
#  elif defined(_WINDOWS)
#    include <malloc.h>
#    define malloc_usable_size _msize
#  elif defined(__FreeBSD__)
#    include <malloc_np.h>
#  else
#    include <malloc.h>
#  endif
#endif

#ifdef WITH_MEMORY_TRACKING
static unsigned long memcount = 0;
static unsigned long max_memcount = 0;
static size_t mem_limit = 0;
#endif

void ts__memory_set_limit(size_t lim) {
  mem_limit = lim;
}

void *ts__calloc(size_t nmemb, size_t size) {
  void *mem;

#ifdef WITH_MEMORY_TRACKING
  if (mem_limit && memcount + size > mem_limit) {
		return NULL;
	}
#endif

  mem = calloc(nmemb, size);

#ifdef WITH_MEMORY_TRACKING
  if (mem) {
		memcount += malloc_usable_size(mem);
		if (memcount > max_memcount) {
			max_memcount = memcount;
		}
	}
#endif

  return mem;
}

void ts__free(void *mem) {
#ifdef WITH_MEMORY_TRACKING
  if (!mem) {
		return;
	}
	memcount -= malloc_usable_size(mem);
#endif
  
  free(mem);
}

void *ts__malloc(size_t size) {
  void *mem;

#ifdef WITH_MEMORY_TRACKING
  if (mem_limit && memcount + size > mem_limit) {
		return NULL;
	}
#endif

  mem = malloc(size);

#ifdef WITH_MEMORY_TRACKING
  if (mem) {
		memcount += malloc_usable_size(mem);
		if (memcount > max_memcount) {
			max_memcount = memcount;
		}
	}
#endif

  return mem;
}

#ifdef WITH_MEMORY_TRACKING
unsigned long ts__memory_used(void) {
	return memcount;
}

unsigned long ts__max_memory_used(void) {
	return max_memcount;
}
#endif

void *ts__realloc(void *ptr, size_t size) {
  void *mem;
  
#ifdef WITH_MEMORY_TRACKING
  if (mem_limit && memcount + size > mem_limit) {
		return NULL;
	}
	if (ptr) {
		memcount -= malloc_usable_size(ptr);
	}
#endif
  
  mem = realloc(ptr, size);

#ifdef WITH_MEMORY_TRACKING
  if (mem) {
		memcount += malloc_usable_size(mem);
		if (memcount > max_memcount) {
			max_memcount = memcount;
		}
	}
#endif

  return mem;
}

char *ts__strdup(const char *s) {
  char *str;
  
#ifdef WITH_MEMORY_TRACKING
  if (mem_limit && memcount + strlen(s) > mem_limit) {
		return NULL;
	}
#endif

  str = strdup(s);

#ifdef WITH_MEMORY_TRACKING
  if (str) {
		memcount += malloc_usable_size(str);
		if (memcount > max_memcount) {
			max_memcount = memcount;
		}
	}
#endif

  return str;
}
