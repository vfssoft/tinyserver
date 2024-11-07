

#ifndef TINYSERVER_TS_TLS_H
#define TINYSERVER_TS_TLS_H

#include "ts_internal.h"

struct ts_tls_s {
    BIO*     appbio; // Application BIO, all IO should be done by this
    BIO*     sslbio; // SSL BIO, only used by OpenSSL
    SSL*     ssl;
    SSL_CTX* ctx;
    int      state;
    ts_tcp_conn_t* conn;
    ts_error_t err;
};

void ts_tls__ctx_init(
    SSL_CTX** ssl_ctx,
    ts_error_t* errt,
    const char* cert,
    const char* key,
    int verify_mode
);
void ts_tls__ctx_destroy(SSL_CTX* ctx);

int ts_tls__init(ts_tls_t* tls, ts_tcp_conn_t* conn);
int ts_tls__destroy(ts_tls_t* tls);
int ts_tls__state(ts_tls_t* tls);
int ts_tls__handshake(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output);
int ts_tls__decrypt(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output);
int ts_tls__encrypt(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output);
int ts_tls__disconnect(ts_tls_t* tls, ts_buf_t* output);

#endif //TINYSERVER_TS_TLS_H
