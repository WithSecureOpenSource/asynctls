#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>

#include "asynctls_version.h"
#include "tls_underlying.h"

ssize_t tls_read_encrypted_output(tls_conn_t *conn, void *buf, size_t count)
{
    errno = EPROTONOSUPPORT;
    return -1;
}

ssize_t tls_read_plain_input(tls_conn_t *conn, void *buf, size_t count)
{
    errno = EPROTONOSUPPORT;
    return -1;
}

int tls_perform_handshake(tls_conn_t *conn)
{
    errno = EPROTONOSUPPORT;
    return -1;
}

tls_ca_bundle_t *make_tls_ca_bundle(const char *pem_file_pathname,
                                    const char *pem_dir_pathname)
{
    return (tls_ca_bundle_t *) make_tls_ca_bundle;
}

void destroy_tls_ca_bundle(tls_ca_bundle_t *ca_bundle) {}

tls_credentials_t *make_tls_credentials(const char *pem_cert_chain_pathname,
                                        const char *pem_priv_key_pathname)
{
    return (tls_credentials_t *) make_tls_credentials;
}

tls_credentials_t *make_tls_credentials_2(const char *pem_cert_chain_pathname,
                                          const char *pem_priv_key_pathname,
                                          const char *password)
{
    return (tls_credentials_t *) make_tls_credentials_2;
}

void destroy_tls_credentials(tls_credentials_t *credentials) {}

void tls_initialize_underlying_client_tech(tls_conn_t *conn) {}

void tls_initialize_underlying_server_tech(tls_conn_t *conn) {}

void tls_free_underlying_resources(tls_conn_t *conn) {}
