#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <async/drystream.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#include "asynctls_version.h"
#include "tls_underlying.h"

static SSL_CTX *system_ctx = NULL;

static void openssl_initialize(void)
{
    static bool initialized = false;
    if (initialized)
        return;
    initialized = true;
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OPENSSL_add_all_algorithms_noconf();
    SSL_library_init();
}

typedef struct {
    uint8_t bytes[2000];
    size_t begin, end;
} buffer_t;

typedef struct {
    SSL *ssl;
    BIO *encrypted_input_bio;  /* write encrypted data into this bio */
    BIO *encrypted_output_bio; /* read encrypted data from this bio */
    buffer_t plain_output_buffer;
    buffer_t encrypted_input_buffer;
} openssl_tech_t;

typedef enum {
    CA_BUNDLE_SYSTEM,          /* use global root certs */
    CA_BUNDLE_OPENSSL_CONTEXT, /* use given root certs */
    CA_BUNDLE_SYNTHETIC,       /* refer to a callback function */
    CA_BUNDLE_PINNED,          /* accept only given leaf certificates */
} ca_bundle_type_t;

typedef struct {
    uint8_t *content;
    size_t size;
} blob_t;

struct tls_ca_bundle {
    ca_bundle_type_t bundle_type;
    int ref_count;
    union {
        struct {
            SSL_CTX *ctx;
        } openssl_context;
        struct {
            bool (*verify)(void *user_data);
            void *user_data;
        } synthetic;
        struct {
            list_t *leaf_certificates; /* of blob_t */
        } pinned;
    };
};

struct tls_credentials {
    uint64_t uid;
    SSL_CTX *ssl_ctx;
    list_t *allowed_protocols;
};

static tls_ca_bundle_t system_ca_bundle = {
    .bundle_type = CA_BUNDLE_SYSTEM,
};

tls_ca_bundle_t *TLS_SYSTEM_CA_BUNDLE = &system_ca_bundle;

static void buffer_reset(buffer_t *buffer)
{
    buffer->begin = buffer->end = 0;
}

static uint8_t *buffer_at(buffer_t *buffer)
{
    return buffer->bytes + buffer->begin;
}

static size_t buffer_remaining(buffer_t *buffer)
{
    return buffer->end - buffer->begin;
}

static void buffer_consume(buffer_t *buffer, size_t count)
{
    buffer->begin += count;
}

static openssl_tech_t *tech(tls_conn_t *conn)
{
    return conn->underlying_tech;
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_READ, "UID=%64u LEN=%d RET=%d");
FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_READ_DUMP, "UID=%64u DATA=%B");

static int bio_read(tls_conn_t *conn, void *buf, int len)
{
    int ret = BIO_read(tech(conn)->encrypted_output_bio, buf, len);
    FSTRACE(ASYNCTLS_OPENSSL_BIO_READ, conn->uid, len, ret);
    FSTRACE(ASYNCTLS_OPENSSL_BIO_READ_DUMP, conn->uid, buf, (ssize_t) ret);
    return ret;
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_SHOULD_RETRY, "UID=%64u RETRY=%s");

static bool bio_should_retry(tls_conn_t *conn)
{
    if (BIO_should_retry(tech(conn)->encrypted_output_bio)) {
        FSTRACE(ASYNCTLS_OPENSSL_BIO_SHOULD_RETRY, conn->uid, "true");
        return true;
    }
    FSTRACE(ASYNCTLS_OPENSSL_BIO_SHOULD_RETRY, conn->uid, "false");
    return false;
}

static ssize_t shutting_down_outgoing(tls_conn_t *conn, void *buf, size_t count)
{
    assert(conn->state == TLS_CONN_STATE_SHUT_DOWN_OUTGOING);
    int ret = bio_read(conn, buf, count);
    if (ret > 0)
        return ret;
    if (!bio_should_retry(conn))
        return 0;
    errno = EAGAIN;
    return -1;
}

static int deny_access(tls_conn_t *conn)
{
    tls_set_conn_state(conn, TLS_CONN_STATE_DENIED);
    errno = EACCES;
    return -1;
}

static int declare_protocol_error(tls_conn_t *conn)
{
    tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
    errno = EPROTO;
    return -1;
}

static int cb_pem_password(char *buf, int size, int rwflag, void *userdata)
{
    strncpy(buf, (const char *) userdata, size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_WRITE, "UID=%64u NUM=%d RET=%d");
FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_WRITE_DUMP, "UID=%64u DATA=%B");

static int ssl_write(tls_conn_t *conn, const void *buf, int num)
{
    ERR_clear_error();
    int ret = SSL_write(tech(conn)->ssl, buf, num);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_WRITE, conn->uid, num, ret);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_WRITE_DUMP, conn->uid, buf, (ssize_t) ret);
    return ret;
}

static const char *trace_ssl_error(void *perror)
{
    switch (*(int *) perror) {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_GET_ERROR,
             "UID=%64u RET=%d ERROR=%I ERRNO=%e");

FSTRACE_DECL(ASYNCTLS_OPENSSL_ERR_GET_ERROR, "UID=%64u ERROR=%s");

static int ssl_get_error(tls_conn_t *conn, int ret)
{
    int error = SSL_get_error(tech(conn)->ssl, ret);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_ERROR, conn->uid, ret, trace_ssl_error,
            &error);
    switch (error) {
        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL: {
            unsigned long thread_error = ERR_get_error();
            char buf[256];
            ERR_error_string_n(thread_error, buf, sizeof buf);
            FSTRACE(ASYNCTLS_OPENSSL_ERR_GET_ERROR, conn->uid, buf);
            break;
        }
        default:
            break;
    }
    return error;
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_SHUTDOWN, "UID=%64u RET=%d");

static int ssl_shutdown(tls_conn_t *conn)
{
    int ret = SSL_shutdown(tech(conn)->ssl);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_SHUTDOWN, conn->uid, ret);
    return ret;
}

static ssize_t relay_encrypted_output(tls_conn_t *conn, void *buf, size_t count)
{
    for (;;) {
        int ret = bio_read(conn, buf, count);
        if (ret > 0)
            return ret;
        if (!bio_should_retry(conn))
            return 0;
        buffer_t *buffer = &tech(conn)->plain_output_buffer;
        if (buffer_remaining(buffer) == 0) {
            ssize_t n = bytestream_1_read(conn->plain_output_stream,
                                          buffer->bytes, sizeof buffer->bytes);
            if (n == 0)
                break;
            if (n < 0)
                return -1;
            buffer->begin = 0;
            buffer->end = n;
        }
        int nn = ssl_write(conn, buffer_at(buffer), buffer_remaining(buffer));
        if (nn <= 0)
            switch (ssl_get_error(conn, nn)) {
                default:
                    return declare_protocol_error(conn);
                case SSL_ERROR_WANT_READ:
                    tls_notify_transport(conn);
                    tls_notify_application(conn);
                    errno = EAGAIN;
                    return -1;
                case SSL_ERROR_WANT_WRITE:
                    abort();
            }
        buffer_consume(buffer, nn);
    }
    tls_set_conn_state(conn, TLS_CONN_STATE_SHUT_DOWN_OUTGOING);
    bytestream_1_close_relaxed(conn->async, conn->plain_output_stream);
    conn->plain_output_stream = drystream;
    int ret = ssl_shutdown(conn);
    if (ret < 0)
        return declare_protocol_error(conn);
    return shutting_down_outgoing(conn, buf, count);
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_DO_HANDSHAKE, "UID=%64u RET=%d");

static int ssl_do_handshake(tls_conn_t *conn)
{
    ERR_clear_error();
    int ret = SSL_do_handshake(tech(conn)->ssl);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_DO_HANDSHAKE, conn->uid, ret);
    return ret;
}

static ssize_t relay_handshake(tls_conn_t *conn, void *buf, size_t count)
{
    for (;;) {
        int ret = bio_read(conn, buf, count);
        if (ret > 0)
            return ret;
        if (!bio_should_retry(conn))
            return 0;
        switch (ssl_get_error(conn, ssl_do_handshake(conn))) {
            case SSL_ERROR_NONE:
                tls_set_conn_state(conn, TLS_CONN_STATE_OPEN);
                return relay_encrypted_output(conn, buf, count);
            case SSL_ERROR_ZERO_RETURN:
                return deny_access(conn);
            case SSL_ERROR_WANT_READ:
                tls_notify_application(conn);
                errno = EAGAIN;
                return -1;
            case SSL_ERROR_WANT_WRITE:
                abort();
            default:
                return declare_protocol_error(conn);
        }
    }
}

ssize_t tls_read_encrypted_output(tls_conn_t *conn, void *buf, size_t count)
{
    if (count > INT_MAX)
        count = INT_MAX;
    switch (conn->state) {
        case TLS_CONN_STATE_HANDSHAKING:
            return relay_handshake(conn, buf, count);
        case TLS_CONN_STATE_OPEN:
            return relay_encrypted_output(conn, buf, count);
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            return shutting_down_outgoing(conn, buf, count);
        case TLS_CONN_STATE_DENIED:
            errno = EACCES;
            return -1;
        case TLS_CONN_STATE_ERRORED:
            errno = EPROTO;
            return -1;
        case TLS_CONN_STATE_ZOMBIE:
            errno = EBADF;
            return -1;
        default:
            abort();
    }
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_SET_BUF_MEM_EOF_RETURN,
             "UID=%64u VALUE=%64d");

static void bio_set_buf_mem_eof_return(tls_conn_t *conn, long value)
{
    FSTRACE(ASYNCTLS_OPENSSL_BIO_SET_BUF_MEM_EOF_RETURN, conn->uid,
            (int64_t) value);
    BIO_ctrl(tech(conn)->encrypted_input_bio, BIO_C_SET_BUF_MEM_EOF_RETURN,
             value, NULL);
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_WRITE, "UID=%64u LEN=%d RET=%d");
FSTRACE_DECL(ASYNCTLS_OPENSSL_BIO_WRITE_DUMP, "UID=%64u DATA=%B");

static ssize_t bio_write(tls_conn_t *conn, const void *buf, int len)
{
    int ret = BIO_write(tech(conn)->encrypted_input_bio, buf, len);
    FSTRACE(ASYNCTLS_OPENSSL_BIO_WRITE, conn->uid, len, ret);
    FSTRACE(ASYNCTLS_OPENSSL_BIO_WRITE_DUMP, conn->uid, buf, (ssize_t) ret);
    return ret;
}

static int perform_encrypted_io(tls_conn_t *conn)
{
    buffer_t *buffer = &tech(conn)->encrypted_input_buffer;
    if (buffer_remaining(buffer) == 0) {
        ssize_t n = bytestream_1_read(conn->encrypted_input_stream,
                                      buffer->bytes, sizeof buffer->bytes);
        if (n == 0) {
            bio_set_buf_mem_eof_return(conn, 0);
            return 0;
        }
        if (n < 0)
            return -1;
        buffer->begin = 0;
        buffer->end = n;
    }
    /* Any BIO_write may create a need for a BIO_read call: */
    tls_notify_transport(conn);
    int count = bio_write(conn, buffer_at(buffer), buffer_remaining(buffer));
    if (count < 0) {
        errno = EAGAIN;
        return -1;
    }
    if (count == 0)
        return declare_protocol_error(conn);
    buffer_consume(buffer, count);
    return 0;
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_READ, "UID=%64u LEN=%d RET=%d");
FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_READ_DUMP, "UID=%64u DATA=%B");

static int ssl_read(tls_conn_t *conn, void *buf, int num)
{
    ERR_clear_error();
    int ret = SSL_read(tech(conn)->ssl, buf, num);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_READ, conn->uid, num, ret);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_READ_DUMP, conn->uid, buf, (ssize_t) ret);
    return ret;
}

ssize_t tls_read_plain_input(tls_conn_t *conn, void *buf, size_t count)
{
    switch (conn->state) {
        default:
            abort();
        case TLS_CONN_STATE_OPEN:
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:;
    }
    for (;;) {
        int ret = ssl_read(conn, buf, count);
        if (ret > 0)
            return ret;
        switch (ssl_get_error(conn, ret)) {
            case SSL_ERROR_ZERO_RETURN:
                return 0;
            case SSL_ERROR_WANT_WRITE:
                tls_notify_transport(conn);
                errno = EAGAIN;
                return -1;
            case SSL_ERROR_WANT_READ:
                if (perform_encrypted_io(conn) < 0)
                    return -1;
                break;
            case SSL_ERROR_SYSCALL:
                if (errno == 0) {
                    if (conn->suppress_ragged_eofs)
                        return 0;
#ifdef ENODATA
                    errno = ENODATA;
#else
                    errno = ECONNABORTED;
#endif
                }
                return -1;
            default:
                return declare_protocol_error(conn);
        }
    }
}

static const char *trace_tlsext_type(void *ptype)
{
    switch (*(int *) ptype) {
        case TLSEXT_NAMETYPE_host_name:
            return "TLSEXT_NAMETYPE_host_name";
        case TLSEXT_STATUSTYPE_ocsp:
            return "TLSEXT_STATUSTYPE_ocsp";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_GET_SERVERNAME, "UID=%64u TYPE=%I NAME=%s");

static const char *ssl_get_servername(tls_conn_t *conn, int type)
{
    const char *name = SSL_get_servername(tech(conn)->ssl, type);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_SERVERNAME, conn->uid, trace_tlsext_type,
            &type, name);
    return name;
}

static const char *trace_x509_err(void *err)
{
    switch (*(long *) err) {
        case X509_V_OK:
            return "X509_V_OK";
        case X509_V_ERR_UNSPECIFIED:
            return "X509_V_ERR_UNSPECIFIED";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return "X509_V_ERR_UNABLE_TO_GET_CRL";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            return "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            return "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            return "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return "X509_V_ERR_CERT_SIGNATURE_FAILURE";
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            return "X509_V_ERR_CRL_SIGNATURE_FAILURE";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "X509_V_ERR_CERT_NOT_YET_VALID";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "X509_V_ERR_CERT_HAS_EXPIRED";
        case X509_V_ERR_CRL_NOT_YET_VALID:
            return "X509_V_ERR_CRL_NOT_YET_VALID";
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return "X509_V_ERR_CRL_HAS_EXPIRED";
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            return "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            return "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            return "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
        case X509_V_ERR_OUT_OF_MEM:
            return "X509_V_ERR_OUT_OF_MEM";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            return "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return "X509_V_ERR_CERT_CHAIN_TOO_LONG";
        case X509_V_ERR_CERT_REVOKED:
            return "X509_V_ERR_CERT_REVOKED";
        case X509_V_ERR_INVALID_CA:
            return "X509_V_ERR_INVALID_CA";
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            return "X509_V_ERR_PATH_LENGTH_EXCEEDED";
        case X509_V_ERR_INVALID_PURPOSE:
            return "X509_V_ERR_INVALID_PURPOSE";
        case X509_V_ERR_CERT_UNTRUSTED:
            return "X509_V_ERR_CERT_UNTRUSTED";
        case X509_V_ERR_CERT_REJECTED:
            return "X509_V_ERR_CERT_REJECTED";
        case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
            return "X509_V_ERR_SUBJECT_ISSUER_MISMATCH";
        case X509_V_ERR_AKID_SKID_MISMATCH:
            return "X509_V_ERR_AKID_SKID_MISMATCH";
        case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
            return "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH";
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            return "X509_V_ERR_KEYUSAGE_NO_CERTSIGN";
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            return "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER";
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            return "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION";
        case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
            return "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN";
        case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
            return "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION";
        case X509_V_ERR_INVALID_NON_CA:
            return "X509_V_ERR_INVALID_NON_CA";
        case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
            return "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED";
        case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
            return "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE";
        case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
            return "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED";
        case X509_V_ERR_INVALID_EXTENSION:
            return "X509_V_ERR_INVALID_EXTENSION";
        case X509_V_ERR_INVALID_POLICY_EXTENSION:
            return "X509_V_ERR_INVALID_POLICY_EXTENSION";
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            return "X509_V_ERR_NO_EXPLICIT_POLICY";
        case X509_V_ERR_DIFFERENT_CRL_SCOPE:
            return "X509_V_ERR_DIFFERENT_CRL_SCOPE";
        case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
            return "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE";
        case X509_V_ERR_UNNESTED_RESOURCE:
            return "X509_V_ERR_UNNESTED_RESOURCE";
        case X509_V_ERR_PERMITTED_VIOLATION:
            return "X509_V_ERR_PERMITTED_VIOLATION";
        case X509_V_ERR_EXCLUDED_VIOLATION:
            return "X509_V_ERR_EXCLUDED_VIOLATION";
        case X509_V_ERR_SUBTREE_MINMAX:
            return "X509_V_ERR_SUBTREE_MINMAX";
        case X509_V_ERR_APPLICATION_VERIFICATION:
            return "X509_V_ERR_APPLICATION_VERIFICATION";
        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
            return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE";
        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
            return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX";
        case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
            return "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX";
        case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
            return "X509_V_ERR_CRL_PATH_VALIDATION_ERROR";
#ifdef X509_V_ERR_SUITE_B_INVALID_VERSION
        case X509_V_ERR_SUITE_B_INVALID_VERSION:
            return "X509_V_ERR_SUITE_B_INVALID_VERSION";
        case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
            return "X509_V_ERR_SUITE_B_INVALID_ALGORITHM";
        case X509_V_ERR_SUITE_B_INVALID_CURVE:
            return "X509_V_ERR_SUITE_B_INVALID_CURVE";
        case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
            return "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM";
        case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
            return "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED";
        case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
            return "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256";
        case X509_V_ERR_HOSTNAME_MISMATCH:
            return "X509_V_ERR_HOSTNAME_MISMATCH";
        case X509_V_ERR_EMAIL_MISMATCH:
            return "X509_V_ERR_EMAIL_MISMATCH";
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            return "X509_V_ERR_IP_ADDRESS_MISMATCH";
        case X509_V_ERR_INVALID_CALL:
            return "X509_V_ERR_INVALID_CALL";
        case X509_V_ERR_STORE_LOOKUP:
            return "X509_V_ERR_STORE_LOOKUP";
        case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
            return "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION";
#endif
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_SSL_GET_VERIFY_RESULT, "UID=%64u RESULT=%I");

static long ssl_get_verify_result(tls_conn_t *conn)
{
    long err = SSL_get_verify_result(tech(conn)->ssl);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_VERIFY_RESULT, conn->uid, trace_x509_err,
            &err);
    return err;
}

static bool verify_pinned_cert(X509 *cert, blob_t *pinned)
{
    size_t size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    if (size != pinned->size)
        return false;
    uint8_t serialization[size];
    uint8_t *endp = serialization;
    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &endp);
    return memcmp(serialization, pinned->content, size) == 0;
}

static bool verify_server(tls_conn_t *conn)
{
    switch (conn->client.ca_bundle->bundle_type) {
        case CA_BUNDLE_SYSTEM:
        case CA_BUNDLE_OPENSSL_CONTEXT:
            return true;
        case CA_BUNDLE_SYNTHETIC: {
            void *user_data = conn->client.ca_bundle->synthetic.user_data;
            return conn->client.ca_bundle->synthetic.verify(user_data);
        }
        case CA_BUNDLE_PINNED: {
            bool valid = false;
            X509 *cert = SSL_get_peer_certificate(tech(conn)->ssl);
            list_t *pinned = conn->client.ca_bundle->pinned.leaf_certificates;
            list_elem_t *e;
            for (e = list_get_first(pinned); e; e = list_next(e)) {
                blob_t *blob = (blob_t *) list_elem_get_value(e);
                if (verify_pinned_cert(cert, blob)) {
                    valid = true;
                    break;
                }
            }
            X509_free(cert);
            return valid;
        }
        default:
            assert(false);
    }
}

static int finish_handshake(tls_conn_t *conn)
{
    async_execute(conn->async, conn->handshake_done_callback);
    if (!conn->is_client)
        conn->server_name = ssl_get_servername(conn, TLSEXT_NAMETYPE_host_name);
    else if (!verify_server(conn))
        return deny_access(conn);
    tls_set_conn_state(conn, TLS_CONN_STATE_OPEN);
    const unsigned char *data;
    unsigned len;
    SSL_get0_alpn_selected(tech(conn)->ssl, &data, &len);
    if (len) {
        char *choice =
            charstr_dupsubstr((const char *) data, (const char *) data + len);
        tls_set_alpn_choice(conn, choice);
    }
    return 0;
}

int tls_perform_handshake(tls_conn_t *conn)
{
    assert(conn->state == TLS_CONN_STATE_HANDSHAKING);
    for (;;)
        switch (ssl_get_error(conn, ssl_do_handshake(conn))) {
            case SSL_ERROR_NONE:
                return finish_handshake(conn);
            case SSL_ERROR_ZERO_RETURN:
                return deny_access(conn);
            case SSL_ERROR_WANT_READ:
                if (perform_encrypted_io(conn) < 0)
                    return -1;
                break;
            case SSL_ERROR_WANT_WRITE:
                tls_notify_transport(conn);
                errno = EAGAIN;
                return -1;
            default:
                ssl_get_verify_result(conn);
                return declare_protocol_error(conn);
        }
}

static SSL_CTX *make_client_ctx(void)
{
    openssl_initialize();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    long options =
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    assert(options & (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3));
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    return ssl_ctx;
}

tls_ca_bundle_t *make_tls_ca_bundle(const char *pem_file_pathname,
                                    const char *pem_dir_pathname)
{
    if (pem_file_pathname == NULL && pem_dir_pathname == NULL)
        return TLS_SYSTEM_CA_BUNDLE;
    int ret = 0;
    SSL_CTX *ssl_ctx = make_client_ctx();
    ret = SSL_CTX_load_verify_locations(ssl_ctx, pem_file_pathname,
                                        pem_dir_pathname);
    assert(ret == 1); /* TODO: deal with the error */
    tls_ca_bundle_t *ca_bundle = fsalloc(sizeof *ca_bundle);
    ca_bundle->bundle_type = CA_BUNDLE_OPENSSL_CONTEXT;
    ca_bundle->ref_count = 1;
    ca_bundle->openssl_context.ctx = ssl_ctx;
    return ca_bundle;
}

static bool accept_anything(void *dummy)
{
    return true;
}

tls_ca_bundle_t *make_unverified_tls_ca_bundle()
{
    return make_synthetic_tls_ca_bundle(accept_anything, NULL);
}

tls_ca_bundle_t *make_synthetic_tls_ca_bundle(bool (*verify)(void *user_data),
                                              void *user_data)
{
    tls_ca_bundle_t *ca_bundle = fsalloc(sizeof *ca_bundle);
    ca_bundle->bundle_type = CA_BUNDLE_SYNTHETIC;
    ca_bundle->ref_count = 1;
    ca_bundle->synthetic.verify = verify;
    ca_bundle->synthetic.user_data = user_data;
    return ca_bundle;
}

static blob_t *serialize_cert(X509 *cert)
{
    blob_t *blob = fsalloc(sizeof *blob);
    blob->size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    uint8_t *endp = blob->content = fsalloc(blob->size);
    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &endp);
    return blob;
}

static void append_certs_from(int fd, list_t *list)
{
    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return;
    }
    for (;;) {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if (!cert)
            break; /* EOF or error (can't tell) */
        list_append(list, serialize_cert(cert));
        X509_free(cert);
    }
    fclose(f);
}

tls_ca_bundle_t *make_pinned_tls_ca_bundle(const char *pem_file_pathname,
                                           const char *pem_dir_pathname)
{
    tls_ca_bundle_t *ca_bundle = fsalloc(sizeof *ca_bundle);
    ca_bundle->bundle_type = CA_BUNDLE_PINNED;
    ca_bundle->ref_count = 1;
    ca_bundle->pinned.leaf_certificates = make_list();
    if (pem_file_pathname) {
        int fd = open(pem_file_pathname, O_RDONLY);
        if (fd >= 0)
            append_certs_from(fd, ca_bundle->pinned.leaf_certificates);
    } else if (pem_dir_pathname) {
        DIR *dir = opendir(pem_dir_pathname);
        for (;;) {
            struct dirent *entity = readdir(dir);
            if (!entity)
                break;
            int fd = openat(dirfd(dir), entity->d_name, O_RDONLY);
            if (fd >= 0)
                append_certs_from(fd, ca_bundle->pinned.leaf_certificates);
        }
        closedir(dir);
    }
    return ca_bundle;
}

void destroy_tls_ca_bundle(tls_ca_bundle_t *ca_bundle)
{
    if (ca_bundle->bundle_type == CA_BUNDLE_SYSTEM || --ca_bundle->ref_count)
        return;
    switch (ca_bundle->bundle_type) {
        case CA_BUNDLE_SYNTHETIC:
            break;
        case CA_BUNDLE_OPENSSL_CONTEXT:
            SSL_CTX_free(ca_bundle->openssl_context.ctx);
            break;
        case CA_BUNDLE_PINNED:
            while (!list_empty(ca_bundle->pinned.leaf_certificates)) {
                blob_t *blob = (blob_t *) list_pop_first(
                    ca_bundle->pinned.leaf_certificates);
                fsfree(blob->content);
                fsfree(blob);
            }
            destroy_list(ca_bundle->pinned.leaf_certificates);
            break;
        default:
            assert(false);
    }
    fsfree(ca_bundle);
}

tls_ca_bundle_t *share_tls_ca_bundle(tls_ca_bundle_t *ca_bundle)
{
    ca_bundle->ref_count++;
    return ca_bundle;
}

bool tls_ca_bundle_equal(tls_ca_bundle_t *a, tls_ca_bundle_t *b)
{
    return a == b;
}

tls_credentials_t *make_tls_credentials(const char *pem_cert_chain_pathname,
                                        const char *pem_priv_key_pathname)
{
    return make_tls_credentials_2(pem_cert_chain_pathname,
                                  pem_priv_key_pathname, NULL);
}

tls_credentials_t *make_tls_credentials_2(const char *pem_cert_chain_pathname,
                                          const char *pem_priv_key_pathname,
                                          const char *password)
{
    openssl_initialize();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (1 !=
        SSL_CTX_use_certificate_chain_file(ssl_ctx, pem_cert_chain_pathname)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    if (password) {
        SSL_CTX_set_default_passwd_cb(ssl_ctx, cb_pem_password);
        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *) password);
    }
    if (1 !=
        SSL_CTX_use_PrivateKey_file(ssl_ctx, pem_priv_key_pathname,
                                    SSL_FILETYPE_PEM)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    tls_credentials_t *credentials = fsalloc(sizeof *credentials);
    credentials->uid = fstrace_get_unique_id();
    credentials->ssl_ctx = ssl_ctx;
    credentials->allowed_protocols = NULL;
    return credentials;
}

static void clear_server_protocols(tls_credentials_t *credentials)
{
    list_t *protocols = credentials->allowed_protocols;
    if (protocols) {
        list_foreach(protocols, (void *) fsfree, NULL);
        destroy_list(protocols);
    }
    credentials->allowed_protocols = NULL;
}

void destroy_tls_credentials(tls_credentials_t *credentials)
{
    clear_server_protocols(credentials);
    SSL_CTX_free(credentials->ssl_ctx);
    fsfree(credentials);
}

static void initialize_underlying_tech(tls_conn_t *conn, SSL *ssl)
{
    openssl_initialize();
    conn->underlying_tech = fsalloc(sizeof(openssl_tech_t));
    buffer_reset(&tech(conn)->plain_output_buffer);
    buffer_reset(&tech(conn)->encrypted_input_buffer);
    tech(conn)->ssl = ssl;
    BIO *input_bio = tech(conn)->encrypted_input_bio = BIO_new(BIO_s_mem());
    BIO_ctrl(input_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, NULL);
    BIO *output_bio = tech(conn)->encrypted_output_bio = BIO_new(BIO_s_mem());
    BIO_ctrl(output_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, NULL);
    SSL_set_bio(ssl, input_bio, output_bio);
    SSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
}

static int server_alpn_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned inlen, void *arg)
{
    tls_credentials_t *credentials = arg;
    list_elem_t *e;
    for (e = list_get_first(credentials->allowed_protocols); e;
         e = list_next(e)) {
        const char *protocol = list_elem_get_value(e);
        unsigned cursor = 0;
        while (cursor < inlen) {
            unsigned proto_len = in[cursor++];
            if (cursor + proto_len > inlen)
                return SSL_TLSEXT_ERR_NOACK; /* format violation */
            if (proto_len == strlen(protocol) &&
                !memcmp(protocol, in + cursor, proto_len)) {
                *out = in + cursor;
                *outlen = proto_len;
                return SSL_TLSEXT_ERR_OK;
            }
            cursor += proto_len;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
}

FSTRACE_DECL(ASYNCTLS_CONN_ALLOW_PROTOCOLS, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_CONN_ADD_ALPN, "UID=%64u PROTO=%s");

void tls_allow_protocols(tls_conn_t *conn, const char *protocol, ...)
{
    FSTRACE(ASYNCTLS_CONN_ALLOW_PROTOCOLS, conn->uid);
    assert(conn->is_client);
    unsigned char buffer[1000];
    unsigned cursor = 0;
    va_list ap;
    va_start(ap, protocol);
    while (protocol) {
        FSTRACE(ASYNCTLS_CONN_ADD_ALPN, conn->uid, protocol);
        size_t length = strlen(protocol);
        assert(length < 256);
        assert(sizeof buffer - cursor > length);
        buffer[cursor++] = length;
        memcpy(buffer + cursor, protocol, length);
        cursor += length;
        protocol = va_arg(ap, const char *);
    }
    va_end(ap);
    SSL_set_alpn_protos(tech(conn)->ssl, buffer, cursor);
}

FSTRACE_DECL(ASYNCTLS_CREDS_SET_PROTOCOLS, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_CREDS_ADD_ALPN, "UID=%64u PROTO=%s");

void tls_set_protocol_priority(tls_credentials_t *credentials,
                               const char *protocol, ...)
{
    FSTRACE(ASYNCTLS_CREDS_SET_PROTOCOLS, credentials->uid);
    clear_server_protocols(credentials);
    credentials->allowed_protocols = make_list();
    va_list ap;
    va_start(ap, protocol);
    while (protocol) {
        FSTRACE(ASYNCTLS_CREDS_ADD_ALPN, credentials->uid, protocol);
        list_append(credentials->allowed_protocols, charstr_dupstr(protocol));
        protocol = va_arg(ap, const char *);
    }
    va_end(ap);
    SSL_CTX_set_alpn_select_cb(credentials->ssl_ctx, server_alpn_cb,
                               credentials);
}

void tls_initialize_underlying_client_tech(tls_conn_t *conn)
{
    SSL_CTX *ctx;
    switch (conn->client.ca_bundle->bundle_type) {
        case CA_BUNDLE_SYSTEM:
        case CA_BUNDLE_SYNTHETIC:
        case CA_BUNDLE_PINNED:
            if (!system_ctx) {
                openssl_initialize();
                system_ctx = make_client_ctx();
                int ret = SSL_CTX_set_default_verify_paths(system_ctx);
                assert(ret == 1); /* TODO: deal with the error */
            }
            ctx = system_ctx;
            break;
        case CA_BUNDLE_OPENSSL_CONTEXT:
            ctx = conn->client.ca_bundle->openssl_context.ctx;
            break;
        default:
            assert(false);
    }
    SSL *ssl = SSL_new(ctx);
    switch (conn->client.ca_bundle->bundle_type) {
        case CA_BUNDLE_SYSTEM:
        case CA_BUNDLE_OPENSSL_CONTEXT:
            /* TODO: deal with the error */
            assert(SSL_set1_host(ssl, conn->server_name) == 1);
            SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
            break;
        default:
            break;
    }
    initialize_underlying_tech(conn, ssl);
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
             (char *) conn->server_name);
    SSL_set_connect_state(ssl);
}

void tls_initialize_underlying_server_tech(tls_conn_t *conn)
{
    SSL *ssl = SSL_new(conn->server.credentials->ssl_ctx);
    initialize_underlying_tech(conn, ssl);
    ERR_clear_error();
    int ret = SSL_accept(ssl);
    assert(ret == -1);
    ret = SSL_get_error(ssl, ret);
    assert(ret == SSL_ERROR_WANT_READ);
}

void tls_adopt_tech(tls_conn_t *conn, void *_ssl)
{
    SSL *ssl = (SSL *) _ssl;

    conn->underlying_tech = fsalloc(sizeof(openssl_tech_t));
    buffer_reset(&tech(conn)->plain_output_buffer);
    buffer_reset(&tech(conn)->encrypted_input_buffer);
    tech(conn)->ssl = ssl;

    tech(conn)->encrypted_input_bio = SSL_get_rbio(ssl);
    BIO_ctrl(tech(conn)->encrypted_input_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1,
             NULL);

    tech(conn)->encrypted_output_bio = SSL_get_wbio(ssl);
    BIO_ctrl(tech(conn)->encrypted_output_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1,
             NULL);

    SSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
}

void tls_free_underlying_resources(tls_conn_t *conn)
{
    SSL_free(tech(conn)->ssl);
    fsfree(tech(conn));
}
