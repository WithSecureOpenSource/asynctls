#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <fstrace.h>
#include <fsdyn/fsalloc.h>
#include <fsdyn/charstr.h>
#include <async/drystream.h>
#include "tls_underlying.h"
#include "asynctls_version.h"

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
    BIO *encrypted_input_bio;   /* write encrypted data into this bio */
    BIO *encrypted_output_bio;  /* read encrypted data from this bio */
    buffer_t plain_output_buffer;
    buffer_t encrypted_input_buffer;
} openssl_tech_t;

typedef enum {
    CA_BUNDLE_SYSTEM,           /* use global root certs */
    CA_BUNDLE_OPENSSL_CONTEXT,  /* use given root certs */
    CA_BUNDLE_SYNTHETIC,        /* refer to a callback function */
    CA_BUNDLE_PINNED,           /* accept only given leaf certificates */
} ca_bundle_type_t;

typedef struct {
    uint8_t *content;
    size_t size;
} blob_t;

struct tls_ca_bundle {
    ca_bundle_type_t bundle_type;
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

static tls_ca_bundle_t system_ca_bundle = {
    .bundle_type = CA_BUNDLE_SYSTEM
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

static ssize_t shutting_down_outgoing(tls_conn_t *conn,
                                      void *buf, size_t count)
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

FSTRACE_DECL(ASYNCTLS_OPENSSL_ERR_GET_ERROR,
             "UID=%64u ERROR=%s");

static int ssl_get_error(tls_conn_t *conn, int ret)
{
    int error = SSL_get_error(tech(conn)->ssl, ret);
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_ERROR,
            conn->uid, ret, trace_ssl_error, &error);
    switch (error) {
        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL: {
            unsigned long thread_error = ERR_get_error();
            char buf[256];
            ERR_error_string_n(thread_error, buf, sizeof buf);
            FSTRACE(ASYNCTLS_OPENSSL_ERR_GET_ERROR,
                    conn->uid, buf);
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
    FSTRACE(ASYNCTLS_OPENSSL_BIO_SET_BUF_MEM_EOF_RETURN,
            conn->uid, (int64_t) value);
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
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            ;
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
                if (errno == 0)
                    errno = ENODATA;
                return -1;
            default:
                return declare_protocol_error(conn);
        }
    }
}

/* Return false for a mismatch
   Compares with wildcard (*) check if allowed
*/
static bool compare_label(const char *host, const char *common,
                          const char *hostend, const char *commonend,
                          bool wildcard_allowed)
{
    /* Host name can't be shorter than common. The only exception is where
     * common name contains single wildcard which would match empty string.
     * Common name might contain wildcard so it can be shorter. */
    size_t host_length = hostend - host;
    size_t common_length = commonend - common;
    if (!wildcard_allowed && (host_length != common_length)) {
        return false;
    }
    if (wildcard_allowed && (host_length < (common_length - 1))) {
        return false;
    }

    while(host < hostend || common < commonend) {
        if (host == hostend && common != commonend) {
            /* Host name has ended, common has one more character left. Verify
             * that it is a wildcard or else the labels don't match. */
            return *common == '*';
        }
        char host_char = charstr_lcase_char(*host);
        char common_char = charstr_lcase_char(*common);
        if (wildcard_allowed && common_char == '*') {
            common += 1;
            /* Move host to point to a string with same amount of characters
             * length as common name has after wildcard. Lengths are validated
             * at the beginning. */
            host = hostend - (commonend - common);

            /* Only one wildcard is allowed */
            wildcard_allowed = false;
        } else {
            if (host_char != common_char) {
                return false;
            }
            host += 1;
            common += 1;
        }
    }
    return true;
}

/* Validate requested hostname against a hostname in X509 certificate.
 *
 * The implementation follows RFC6125 with these notes:
 *  - Internationalized Domain Names are not supported
 *  - Comparing domain names is case-insensitive with ASCII characters
 *  - Wildcard certificates checking is not as strict as specified in
 *    Section 6.4.3 (check below for more clarification)
 *
 * Wildcard certificates checking is relaxed with couple points specified in
 * Section 7.2. The implemented checking follows these rules:
 *  - Wildcard may be present in any label except in the right-most label
 *  - Wildcard may contain prefix and/or suffix in the label where it is
 *  - Only one wildcard is allowed in single label (second one is not consider )
 */
static bool compare_hostname(const char *hostpos, const char *commonpos)
{
    bool wildcard_allowed = true;
    for (;;) {
        const char *hostend = strchr(hostpos, '.');
        const char *commonend = strchr(commonpos, '.');

        if (hostend == NULL || commonend == NULL) {
            if (hostend != commonend) {
                return false;
            }

            /* Wildcard is not allowed in the right-most label */
            wildcard_allowed = false;
            hostend = strchr(hostpos, '\0');
            commonend = strchr(commonpos, '\0');
        }

        if (!compare_label(hostpos, commonpos, hostend, commonend,
                wildcard_allowed)) {
            return false;
        }

        if (*hostend == '\0') {
            return true;
        }

        hostpos = hostend + 1;
        commonpos = commonend + 1;
    }
}

static const char *trace_gen_name_type(void *ptype)
{
    switch (*(int *) ptype) {
        case GEN_OTHERNAME:
            return "GEN_OTHERNAME";
        case GEN_EMAIL:
            return "GEN_EMAIL";
        case GEN_DNS:
            return "GEN_DNS";
        case GEN_X400:
            return "GEN_X400";
        case GEN_DIRNAME:
            return "GEN_DIRNAME";
        case GEN_EDIPARTY:
            return "GEN_EDIPARTY";
        case GEN_URI:
            return "GEN_URI";
        case GEN_IPADD:
            return "GEN_IPADD";
        case GEN_RID:
            return "GEN_RID";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_ALT_NAME_COUNT, "UID=%64u N=%d");
FSTRACE_DECL(ASYNCTLS_OPENSSL_ALT_NAME_TYPE, "UID=%64u I=%d TYPE=%I");
FSTRACE_DECL(ASYNCTLS_OPENSSL_ALT_NAME_EVIL, "UID=%64u I=%d ALT-NAME=%A");
FSTRACE_DECL(ASYNCTLS_OPENSSL_ALT_NAME_MATCH,
             "UID=%64u I=%d ALT-NAME=%s SERVER-NAME=%s");
FSTRACE_DECL(ASYNCTLS_OPENSSL_ALT_NAME_MISMATCH,
             "UID=%64u I=%d ALT-NAME=%s SERVER-NAME=%s");

/* Return false for a mismatch. */
static bool compare_cert_sub_names(tls_conn_t *conn, X509 *peer)
{
    struct stack_st *san_names =
        X509_get_ext_d2i(peer, NID_subject_alt_name, NULL, NULL);
    int san_names_nb = sk_num(san_names);
    FSTRACE(ASYNCTLS_OPENSSL_ALT_NAME_COUNT, conn->uid, san_names_nb);
    int result = false;
    int i;
    for (i = 0; i < san_names_nb; i++) {
        const GENERAL_NAME *current_name =
            (GENERAL_NAME *) sk_value(san_names, i);
        FSTRACE(ASYNCTLS_OPENSSL_ALT_NAME_TYPE,
                conn->uid, i, trace_gen_name_type, &current_name->type);
        if (current_name->type == GEN_DNS) {
            const char *dns_name =
                (char *) ASN1_STRING_get0_data(current_name->d.dNSName);
            /* Make sure there isn't an embedded NUL in the DNS name */
            size_t length = ASN1_STRING_length(current_name->d.dNSName);
            if (length != strlen(dns_name)) {
                FSTRACE(ASYNCTLS_OPENSSL_ALT_NAME_EVIL,
                        conn->uid, i, dns_name, length);
                break;
            }
            if (compare_hostname(conn->server_name, dns_name)) {
                FSTRACE(ASYNCTLS_OPENSSL_ALT_NAME_MATCH,
                        conn->uid, i, dns_name, conn->server_name);
                result = true;
                break;
            }
            FSTRACE(ASYNCTLS_OPENSSL_ALT_NAME_MISMATCH,
                    conn->uid, i, dns_name, conn->server_name);
        }
    }
    sk_pop_free(san_names, (void (*)(void *)) GENERAL_NAME_free);
    return result;
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
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_SERVERNAME,
            conn->uid, trace_tlsext_type, &type, name);
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
    FSTRACE(ASYNCTLS_OPENSSL_SSL_GET_VERIFY_RESULT,
            conn->uid, trace_x509_err, &err);
    return err;
}

FSTRACE_DECL(ASYNCTLS_OPENSSL_NO_PEER_NAME, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_OPENSSL_COMMON_NAME_MATCH,
             "UID=%64u COMMON-NAME=%s SERVER-NAME=%s");
FSTRACE_DECL(ASYNCTLS_OPENSSL_COMMON_NAME_MISMATCH,
             "UID=%64u COMMON-NAME=%s SERVER-NAME=%s");

static bool verify_cert(tls_conn_t *conn)
{
    if (ssl_get_verify_result(conn) != X509_V_OK)
        return false;
    X509 *peer = SSL_get_peer_certificate(tech(conn)->ssl);
    X509_NAME *name = X509_get_subject_name(peer);
    if (!name) {
        FSTRACE(ASYNCTLS_OPENSSL_NO_PEER_NAME, conn->uid);
        X509_free(peer);
        return false;
    }
    if (!compare_cert_sub_names(conn, peer)) {
        char peer_CN[256];
        X509_NAME_get_text_by_NID(name, NID_commonName,
                                      peer_CN, sizeof peer_CN);
        if (!compare_hostname(conn->server_name, peer_CN)) {
            FSTRACE(ASYNCTLS_OPENSSL_COMMON_NAME_MISMATCH,
                    conn->uid, peer_CN, conn->server_name);
            X509_free(peer);
            return false;
        }
        FSTRACE(ASYNCTLS_OPENSSL_COMMON_NAME_MATCH,
                conn->uid, peer_CN, conn->server_name);
    }
    X509_free(peer);
    return true;
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
            return verify_cert(conn);
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
    if (!conn->is_client) {
        conn->server_name = ssl_get_servername(conn, TLSEXT_NAMETYPE_host_name);
        tls_set_conn_state(conn, TLS_CONN_STATE_OPEN);
        return 0;
    }
    if (!verify_server(conn))
        return deny_access(conn);
    tls_set_conn_state(conn, TLS_CONN_STATE_OPEN);
    const unsigned char *data;
    unsigned len;
    SSL_get0_alpn_selected(tech(conn)->ssl, &data, &len);
    if (len)
        tls_set_alpn_choice(conn,
                            charstr_dupsubstr((const char *) data,
                                              (const char *) data + len));
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
                return declare_protocol_error(conn);
        }
}

static SSL_CTX *make_client_ctx(void)
{
    openssl_initialize();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    long options = SSL_CTX_set_options(ssl_ctx,
                                    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
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
    assert(ret == 1);           /* TODO: deal with the error */
    tls_ca_bundle_t *ca_bundle = fsalloc(sizeof *ca_bundle);
    ca_bundle->bundle_type = CA_BUNDLE_OPENSSL_CONTEXT;
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

static void append_certs_from(const char *pem_file_pathname, list_t *list)
{
    FILE *f = fopen(pem_file_pathname, "r");
    if (!f)
        return;
    for (;;) {
        X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
        if (!cert)
            break;          /* EOF or error (can't tell) */
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
    ca_bundle->pinned.leaf_certificates = make_list();
    if (pem_file_pathname)
        append_certs_from(pem_file_pathname,
                          ca_bundle->pinned.leaf_certificates);
    else if (pem_dir_pathname) {
       DIR *dir = opendir(pem_dir_pathname);
       for (;;) {
           struct dirent *entity = readdir(dir);
           if (!entity)
               break;
           append_certs_from(entity->d_name,
                             ca_bundle->pinned.leaf_certificates);
       }
       closedir(dir);
    }
    return ca_bundle;
}

void destroy_tls_ca_bundle(tls_ca_bundle_t *ca_bundle)
{
    switch (ca_bundle->bundle_type) {
        case CA_BUNDLE_SYSTEM:
            return;
        case CA_BUNDLE_SYNTHETIC:
            break;
        case CA_BUNDLE_OPENSSL_CONTEXT:
            SSL_CTX_free(ca_bundle->openssl_context.ctx);
            break;
        case CA_BUNDLE_PINNED:
            while (!list_empty(ca_bundle->pinned.leaf_certificates)) {
                blob_t *blob = (blob_t *)
                    list_pop_first(ca_bundle->pinned.leaf_certificates);
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
    if (1 != SSL_CTX_use_certificate_chain_file(ssl_ctx,
            pem_cert_chain_pathname)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    if (password) {
        SSL_CTX_set_default_passwd_cb(ssl_ctx, cb_pem_password);
        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *) password);
    }
    if (1 != SSL_CTX_use_PrivateKey_file(ssl_ctx, pem_priv_key_pathname,
        SSL_FILETYPE_PEM)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    return (tls_credentials_t *) ssl_ctx;
}

void destroy_tls_credentials(tls_credentials_t *credentials)
{
    SSL_CTX_free((SSL_CTX *) credentials);
}

static void initialize_underlying_tech(tls_conn_t *conn, SSL *ssl)
{
    openssl_initialize();
    conn->underlying_tech = fsalloc(sizeof(openssl_tech_t));
    buffer_reset(&tech(conn)->plain_output_buffer);
    buffer_reset(&tech(conn)->encrypted_input_buffer);
    tech(conn)->ssl = ssl;
    BIO *input_bio = tech(conn)->encrypted_input_bio =
        BIO_new(BIO_s_mem());
    BIO_ctrl(input_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, NULL);
    BIO *output_bio = tech(conn)->encrypted_output_bio =
        BIO_new(BIO_s_mem());
    BIO_ctrl(output_bio, BIO_C_SET_BUF_MEM_EOF_RETURN, -1, NULL);
    SSL_set_bio(ssl, input_bio, output_bio);
    SSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
}


FSTRACE_DECL(ASYNCTLS_CONN_ADD_ALPN, "UID=%64u PROTO=%s");

void tls_allow_protocols(tls_conn_t *conn, const char *protocol, ...)
{
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
                assert(ret == 1);           /* TODO: deal with the error */
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
    initialize_underlying_tech(conn, ssl);
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
        TLSEXT_NAMETYPE_host_name, (char *) conn->server_name);
    SSL_set_connect_state(ssl);
}

void tls_initialize_underlying_server_tech(tls_conn_t *conn)
{
    SSL *ssl = SSL_new((SSL_CTX *) conn->server.credentials);
    initialize_underlying_tech(conn, ssl);
    ERR_clear_error();
    int ret = SSL_accept(ssl);
    assert(ret == -1);
    ret = SSL_get_error(ssl, ret);
    assert(ret == SSL_ERROR_WANT_READ);
}

void tls_adopt_tech(tls_conn_t *conn, void *_ssl)
{
    SSL *ssl = (SSL*)_ssl;

    conn->underlying_tech = fsalloc(sizeof(openssl_tech_t));
    buffer_reset(&tech(conn)->plain_output_buffer);
    buffer_reset(&tech(conn)->encrypted_input_buffer);
    tech(conn)->ssl = ssl;

    tech(conn)->encrypted_input_bio = SSL_get_rbio(ssl);
    BIO_ctrl(tech(conn)->encrypted_input_bio, BIO_C_SET_BUF_MEM_EOF_RETURN,
            -1, NULL);

    tech(conn)->encrypted_output_bio = SSL_get_wbio(ssl);
    BIO_ctrl(tech(conn)->encrypted_output_bio, BIO_C_SET_BUF_MEM_EOF_RETURN,
            -1, NULL);

    SSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
}

void tls_free_underlying_resources(tls_conn_t *conn)
{
    SSL_free(tech(conn)->ssl);
    fsfree(tech(conn));
}
