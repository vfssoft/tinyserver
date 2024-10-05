
#ifndef TINYSERVER_TS_INTERNAL_H
#define TINYSERVER_TS_INTERNAL_H

#include <uv.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <stdio.h>

#include "ts.h"
#include "ts_server.h"
#include "ts_tcp_conn.h"
#include "ts_tls.h"
#include "ts_ws.h"
#include "ts_conn__write_req.h"
#include "internal/ts_log.h"
#include "internal/ts_miscellany.h"
#include "internal/ts_crypto.h"
#include "internal/ts_error.h"
#include "internal/ts_mem.h"
#include "internal/utlist.h"

#include <time.h>
#include <inttypes.h>

// help macros
#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef BOOL
#define BOOL int
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif //TINYSERVER_TS_INTERNAL_H
