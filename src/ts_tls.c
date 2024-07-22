
#include "ts_internal.h"

static int openssl_lib_initialized = 0;

static void ts_tls__init_openssl() {
  if (openssl_lib_initialized) {
    return;
  }
  
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  openssl_lib_initialized = 1;
}

static void ts_tls__destroy_openssl() {
  if (!openssl_lib_initialized) {
    return;
  }
  
  ERR_remove_state(0);
  ENGINE_cleanup();
  CONF_modules_unload(1);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  
  openssl_lib_initialized = 0;
}

static void ts_tls__set_err(ts_tls_t* tls, int err) {
  // don't process the error, convert error should be done out side of this function
  tls->ssl_state = TLS_STATE_DISCONNECTED;
  tls->ssl_err = err;
}
static void ts_tls__set_err2(ts_tls_t* tls) {
  tls->ssl_state = TLS_STATE_DISCONNECTED;
  tls->ssl_err = ERR_get_error();
  
  // ref: https://en.wikibooks.org/wiki/OpenSSL/Error_handling
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char *errmsg;
  size_t errmsg_len = BIO_get_mem_data(bio, &errmsg);
  tls->ssl_err_msg = ts_buf__create(0);
  ts_buf__set_str(tls->ssl_err_msg, errmsg, errmsg_len);
  BIO_free(bio);
}

static SSL_CTX* ts_tls__create_ssl_ctx() {
  ts_tls__init_openssl();
  
  SSL_CTX* ctx = SSL_CTX_new(TLS_method());
  if (ctx == NULL) {
    return NULL;
  }
  
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
  
  SSL_CTX_set_mode(
      ctx,
      SSL_MODE_AUTO_RETRY |
      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
      SSL_MODE_ENABLE_PARTIAL_WRITE |
      SSL_MODE_RELEASE_BUFFERS
  );
  
  // #define CIPHERS    "ALL:!EXPORT:!LOW"
  // SSL_CTX_set_cipher_list(ctx, CIPHERS);
  
  return ctx;
}

static void ts_tls__free_ssl_ctx(SSL_CTX* ctx) {
  SSL_CTX_free(ctx);
  ctx = NULL;
}

static int ts_tls__verify_cb(int ok, X509_STORE_CTX* ctx) {
  return 1; // TODO:
}

static int ts_tls__get_openssl_error(int err) {
  if (err == 0 || err == -1 || err == 1) {
    return (int) ERR_get_error();
  } else {
    return err;
  }
}

int ts_tls__init(ts_tls_t* tls) {
  tls->ctx = ts_tls__create_ssl_ctx();
  if (tls->ctx == NULL) {
    return TS_ERR_OUT_OF_MEMORY;
  }
  
  tls->ssl = SSL_new(tls->ctx);
  if (tls->ssl == NULL) {
    return TS_ERR_OUT_OF_MEMORY;
  }
  SSL_set_accept_state(tls->ssl); // server mode
  
  BIO_new_bio_pair(&(tls->sslbio), 0, &(tls->appbio), 0);
  SSL_set_bio(tls->ssl, tls->sslbio, tls->sslbio);
  
  tls->ssl_state = TLS_STATE_HANDSHAKING;
  tls->ssl_err = 0;
  tls->ssl_err_msg = NULL;

  tls->ssl_buf = ts_buf__create(0);
  if (tls->ssl_buf == NULL) {
    return TS_ERR_OUT_OF_MEMORY;
  }
  
  return 0;
}

int ts_tls__destroy(ts_tls_t* tls) {
  // TODO:
  return -1;
}

int ts_tls__set_cert_files(ts_tls_t* tls, const char* cert, const char* key) {
  int err;
  SSL_CTX* ctx = tls->ctx;
  
  err = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
  if (err != 1) {
    ts_tls__set_err2(tls);
    return tls->ssl_err;
  }
  
  err = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
  if (err != 1) {
    ts_tls__set_err2(tls);
    return tls->ssl_err;
  }
  
  err = SSL_CTX_check_private_key(ctx);
  if (err != 1) {
    ts_tls__set_err2(tls);
    return tls->ssl_err;
  }
  
  return 0;
}

int ts_tls__set_verify_mode(ts_tls_t* tls, int mode) {
  // no callback is exposed here, we will handle the certificate verification internally
  SSL_CTX_set_verify(tls->ctx, mode, ts_tls__verify_cb);
  return 0;
}

static int ts_tls__connected(ts_tls_t* tls) {
  return tls->ssl_state == TLS_STATE_CONNECTED;
}

static int ts_tls__get_pending_ssl_data_to_send(ts_tls_t* tls, ts_buf_t* output) {
  int pending = BIO_pending(tls->appbio);
  if (pending > 0) {
    char* tmp = (char*) ts__malloc(pending);
    if (tmp == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
    int len_read = BIO_read(tls->appbio, tmp, pending);
    ts_buf__write(output, tmp, len_read);
    ts__free(tmp);
  }
  return 0;
}
static int ts_tls__write_data_to_ssl(ts_tls_t* tls, ts_ro_buf_t* input) {
  if (input->len > 0) {
    int written = BIO_write(tls->appbio, input->buf, input->len);
    if (written > 0) {
      input->buf += written;
      input->len -= written;
    }
  }
  return 0;
}
static int ts_tls__more_action(ts_tls_t* tls, int hs_err, ts_ro_buf_t* input, ts_buf_t* output) {
  int err;
  int ssl_err;
  
  ssl_err = SSL_get_error(tls->ssl, hs_err);
  
  switch (ssl_err) {
    case SSL_ERROR_NONE:
      break;
    
    case SSL_ERROR_ZERO_RETURN:
      // The TLS/SSL peer has closed the connection for writing by sending the close_notify alert.
      // No more data can be read.
      
      if (tls->ssl_state == TLS_STATE_HANDSHAKING) {
        ts_tls__set_err(tls, UV__ENOTCONN); // not connected successfully
      } else {
        // tls->ssl_state == TLS_STATE_CONNECTED;
        ts_tls__set_err(tls, 0);
      }
      return tls->ssl_err;
      
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      
      err = ts_tls__write_data_to_ssl(tls, input);
      if (err) {
        ts_tls__set_err(tls, err);
        return err;
      }
      
      err = ts_tls__get_pending_ssl_data_to_send(tls, output);
      if (err) {
        ts_tls__set_err(tls, err);
        return err;
      }

      break;
    
    default:
      ts_tls__set_err(tls, ts_tls__get_openssl_error(ssl_err));
      return tls->ssl_err;
  }

  return 0;
}
int ts_tls__handshake(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output) {
  int err;
  int hs_err;
  
  hs_err = SSL_do_handshake(tls->ssl);
  if (hs_err == 1) {
    // The TLS/SSL handshake was successfully completed, a TLS/SSL connection has been established.
    tls->ssl_state = TLS_STATE_CONNECTED;
    return 0;
  } else if (hs_err == 0) {
    // The TLS/SSL handshake was not successful but was shut down controlled and by the specifications of the TLS/SSL protocol.
    ts_tls__set_err(tls, SSL_get_error(tls->ssl, hs_err));
    return tls->ssl_err;
  } else {
    // The TLS/SSL handshake was not successful because a fatal error occurred either at the
    // protocol level or a connection failure occurred. The shutdown was not clean. It can also
    // occur if action is needed to continue the operation for non-blocking BIOs.
    err = ts_tls__more_action(tls, hs_err, input, output);
    return err;
  }
}

int ts_tls__decrypt(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output) {
  int err;
  int ssl_read_ret;
  char ssl_buf[2048];
  
  if (input->len > 0) {
    err = ts_tls__write_data_to_ssl(tls, input);
    if (err) {
      ts_tls__set_err(tls, err);
      return err;
    }
  
    ssl_read_ret = SSL_read(tls->ssl, ssl_buf, 2048);
    if (ssl_read_ret > 0) {
      ts_buf__write(output, ssl_buf, ssl_read_ret);
    } else if (ssl_read_ret == 0) {
      // ref: https://www.openssl.org/docs/man1.1.1/man3/SSL_get_error.html BUGS section
      // peer disconnect first. This is not a real error
      ts_tls__set_err(tls, 0);
    } else {
      ts_tls__set_err(tls, ts_tls__get_openssl_error(ssl_read_ret));
      return tls->ssl_err;
    }
  }
  
  return 0;
}

/*
int ts_tls__process_app_data(ts_tls_t* tls, ts_buf_t* input, ts_buf_t* output) {
  int err = 0;
  
  if (input->len > 0) {
    err = ts_tls__write_or_pending_data_to_ssl(tls, input);
    if (err) {
      ts_tls__set_err(tls, err);
      return err;
    }
  }
  
  err = ts_tls__get_pending_ssl_data_to_send(tls, output);
  if (err) {
    ts_tls__set_err(tls, err);
    return err;
  }
  
  return 0;
}
 */