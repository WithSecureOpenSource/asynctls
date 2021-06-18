#include <Security/Security.h>
#include <assert.h>
#include <errno.h>

#include <async/drystream.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#include "asynctls_version.h"
#include "tls_underlying.h"

typedef struct {
    uint8_t bytes[2000];
    size_t begin, end;
} buffer_t;

typedef struct {
    SSLContextRef ssl;
    buffer_t plain_output_buffer;
    buffer_t encrypted_output_buffer;
} secure_transport_tech_t;

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

static size_t buffer_space(buffer_t *buffer)
{
    return sizeof buffer->bytes - buffer->end;
}

static void buffer_fill(buffer_t *buffer, const void *data, size_t size)
{
    memcpy(buffer->bytes + buffer->end, data, size);
    buffer->end += size;
}

static secure_transport_tech_t *tech(tls_conn_t *conn)
{
    return conn->underlying_tech;
}

static const char *trace_OSStatus(void *status);

FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_WRITE,
             "UID=%64u LENGTH=%z STATUS=%I PROCESSED=%z");
FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_WRITE_DUMP, "UID=%64u DATA=%B");

static OSStatus ssl_write(tls_conn_t *conn, const void *data, size_t dataLength,
                          size_t *processed)
{
    OSStatus status = SSLWrite(tech(conn)->ssl, data, dataLength, processed);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_WRITE, conn->uid, dataLength, trace_OSStatus,
            &status, *processed);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_WRITE_DUMP, conn->uid, data, *processed);
    return status;
}

FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_SPURIOUS, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_WRITE_BLOCKED, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_ABORTED, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_EXHAUSTED, "UID=%64u");
FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_FAIL, "UID=%64u ERRNO=%e");
FSTRACE_DECL(ASYNCTLS_SECTRAN_RELAY_OUTGOING_REPLENISH, "UID=%64u COUNT=%z");

static void declare_protocol_error(tls_conn_t *conn)
{
    tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
    errno = EPROTO;
}

static size_t read_buffered_output(tls_conn_t *conn, void *buf, size_t count)
{
    buffer_t *buffer = &tech(conn)->encrypted_output_buffer;
    size_t remaining = buffer_remaining(buffer);
    if (remaining) {
        if (remaining <= count) {
            count = remaining;
            memcpy(buf, buffer_at(buffer), count);
            buffer_reset(buffer);
        } else {
            memcpy(buf, buffer_at(buffer), count);
            buffer_consume(buffer, count);
        }
        return count;
    }
    return 0;
}

FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_CLOSE, "UID=%64u STATUS=%I");

static ssize_t shutting_down_outgoing(tls_conn_t *conn, void *buf, size_t count)
{
    OSStatus status = SSLClose(tech(conn)->ssl);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_CLOSE, conn->uid, trace_OSStatus, &status);
    switch (status) {
        case errSecSuccess:
            return read_buffered_output(conn, buf, count);
        case errSSLClosedGraceful:
            return 0;
        case errSSLWouldBlock:
            errno = -EAGAIN;
            return -1;
        default:
            declare_protocol_error(conn);
            return -1;
    }
}

static ssize_t relay_encrypted_output(tls_conn_t *conn, void *buf, size_t count)
{
    buffer_t *buffer = &tech(conn)->plain_output_buffer;
    for (;;) {
        size_t ret = read_buffered_output(conn, buf, count);
        if (ret)
            return ret;
        while (buffer_remaining(buffer)) {
            size_t count;
            OSStatus status = ssl_write(conn, buffer_at(buffer),
                                        buffer_remaining(buffer), &count);
            switch (status) {
                case errSecSuccess:
                    buffer_consume(buffer, count);
                    break;
                case errSSLWouldBlock:
                    if (!count) {
                        FSTRACE(ASYNCTLS_SECTRAN_RELAY_OUTGOING_WRITE_BLOCKED,
                                conn->uid);
                        tls_notify_transport(conn);
                        tls_notify_application(conn);
                        errno = EAGAIN;
                        return -1;
                    }
                    buffer_consume(buffer, count);
                    break;
                default:
                    declare_protocol_error(conn);
                    FSTRACE(ASYNCTLS_SECTRAN_RELAY_OUTGOING_ABORTED, conn->uid);
                    return -1;
            }
        }
        buffer_reset(buffer);
        ssize_t n = bytestream_1_read(conn->plain_output_stream,
                                      buffer_at(buffer), buffer_space(buffer));
        if (n == 0) {
            tls_set_conn_state(conn, TLS_CONN_STATE_SHUT_DOWN_OUTGOING);
            FSTRACE(ASYNCTLS_SECTRAN_RELAY_OUTGOING_EXHAUSTED, conn->uid);
            bytestream_1_close_relaxed(conn->async, conn->plain_output_stream);
            conn->plain_output_stream = drystream;
            return shutting_down_outgoing(conn, buf, count);
        }
        if (n < 0) {
            FSTRACE(ASYNCTLS_SECTRAN_RELAY_OUTGOING_FAIL, conn->uid);
            return -1;
        }
        FSTRACE(ASYNCTLS_SECTRAN_RELAY_OUTGOING_REPLENISH, conn->uid, n);
        buffer->end += n;
    }
}

ssize_t tls_read_encrypted_output(tls_conn_t *conn, void *buf, size_t count)
{
    if (count > INT_MAX)
        count = INT_MAX;
    switch (conn->state) {
        case TLS_CONN_STATE_HANDSHAKING: {
            size_t ret = read_buffered_output(conn, buf, count);
            if (ret)
                return ret;
            tls_notify_transport(conn);
            errno = EAGAIN;
            return -1;
        }
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

FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_READ,
             "UID=%64u LENGTH=%z STATUS=%I PROCESSED=%z");
FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_READ_DUMP, "UID=%64u DATA=%B");

static OSStatus ssl_read(tls_conn_t *conn, void *data, size_t dataLength,
                         size_t *processed)
{
    OSStatus status = SSLRead(tech(conn)->ssl, data, dataLength, processed);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_READ, conn->uid, dataLength, trace_OSStatus,
            &status, *processed);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_READ_DUMP, conn->uid, data, *processed);
    return status;
}

ssize_t tls_read_plain_input(tls_conn_t *conn, void *buf, size_t count)
{
    if (!count)
        return count;
    if (count > INT_MAX)
        count = INT_MAX;
    size_t processed;
    OSStatus status = ssl_read(conn, buf, count, &processed);
    switch (status) {
        case errSSLClosedGraceful:
            return 0;
        case errSecSuccess:
            return processed;
        case errSSLWouldBlock:
            if (processed)
                return processed;
            errno = EAGAIN;
            return -1;
        default:
            declare_protocol_error(conn);
            return -1;
    }
}

FSTRACE_DECL(ASYNCTLS_SECTRAN_SSL_HANDSHAKE, "UID=%64u STATUS=%I");

static OSStatus ssl_handshake(tls_conn_t *conn)
{
    OSStatus status = SSLHandshake(tech(conn)->ssl);
    FSTRACE(ASYNCTLS_SECTRAN_SSL_HANDSHAKE, conn->uid, trace_OSStatus, &status);
    return status;
}

int tls_perform_handshake(tls_conn_t *conn)
{
    assert(conn->state == TLS_CONN_STATE_HANDSHAKING);
    OSStatus status = ssl_handshake(conn);
    switch (status) {
        case errSecSuccess:
            async_execute(conn->async, conn->handshake_done_callback);
            tls_set_conn_state(conn, TLS_CONN_STATE_OPEN);
            return 0;
        case errSSLWouldBlock:
            errno = EAGAIN;
            return -1;
        case errSSLClosedAbort:
        case errSSLUnknownRootCert:
        case errSSLNoRootCert:
        case errSSLCertExpired:
        case errSSLXCertChainInvalid:
        case errSSLPeerBadCert:
        case errSSLPeerUnknownCA:
            tls_set_conn_state(conn, TLS_CONN_STATE_DENIED);
            errno = EACCES;
            return -1;
        default:
            assert(false);
    }
}

tls_ca_bundle_t *make_tls_ca_bundle(const char *pem_file_pathname,
                                    const char *pem_dir_pathname)
{
    return TLS_SYSTEM_CA_BUNDLE; /* TODO: implement properly */
}

/* A unique sentinel value != NULL. */
tls_ca_bundle_t *TLS_SYSTEM_CA_BUNDLE = (tls_ca_bundle_t *) make_tls_ca_bundle;

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
    /* TODO: implement */
    assert(false);
}

tls_ca_bundle_t *make_pinned_tls_ca_bundle(const char *pem_file_pathname,
                                           const char *pem_dir_pathname)
{
    /* TODO: implement */
    assert(false);
}

void destroy_tls_ca_bundle(tls_ca_bundle_t *ca_bundle) {}

tls_ca_bundle_t *share_tls_ca_bundle(tls_ca_bundle_t *ca_bundle)
{
    return ca_bundle;
}

bool tls_ca_bundle_equal(tls_ca_bundle_t *a, tls_ca_bundle_t *b)
{
    return a == b;
}

static bool read_file(const char *path, CFMutableDataRef data)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    for (;;) {
        uint8_t buf[4096];
        ssize_t count = read(fd, buf, sizeof buf);
        if (count == 0)
            break;
        if (count > 0)
            CFDataAppendBytes(data, buf, count);
        else if (errno != EINTR) {
            close(fd);
            return false;
        }
    }
    close(fd);
    return true;
}

extern SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator,
                                        SecCertificateRef certificate,
                                        SecKeyRef privateKey);

struct tls_credentials {
    CFArrayRef cert_refs;
};

tls_credentials_t *make_tls_credentials(const char *pem_cert_chain_pathname,
                                        const char *pem_priv_key_pathname)
{
    CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CFArrayRef items = NULL;
    SecIdentityRef id = NULL;
    CFMutableArrayRef cert_refs = NULL;

    if (!read_file(pem_cert_chain_pathname, data))
        goto exit;
    if (!read_file(pem_priv_key_pathname, data))
        goto exit;

    SecExternalFormat format = kSecFormatPEMSequence;
    SecExternalItemType type = kSecItemTypeAggregate;
    OSStatus status =
        SecItemImport(data, NULL, &format, &type, 0, NULL, NULL, &items);
    if (status != noErr)
        goto exit;

    SecCertificateRef cert = NULL;
    SecKeyRef key = NULL;
    for (CFIndex i = 0; i < CFArrayGetCount(items); i++) {
        const void *item = CFArrayGetValueAtIndex(items, i);
        CFTypeID item_id = CFGetTypeID(item);

        if (item_id == SecCertificateGetTypeID())
            cert = (SecCertificateRef) item;
        else if (item_id == SecKeyGetTypeID())
            key = (SecKeyRef) item;
    }
    if (!cert || !key)
        goto exit;

    id = SecIdentityCreate(kCFAllocatorDefault, cert, key);
    if (!id)
        goto exit;

    cert_refs =
        CFArrayCreateMutable(kCFAllocatorDefault, 1, &kCFTypeArrayCallBacks);
    CFArraySetValueAtIndex(cert_refs, 0, id);

exit:
    CFRelease(data);
    if (items)
        CFRelease(items);
    if (id)
        CFRelease(id);
    if (!cert_refs)
        return NULL;
    tls_credentials_t *creds = fsalloc(sizeof *creds);
    creds->cert_refs = cert_refs;
    return creds;
}

tls_credentials_t *make_tls_credentials_2(const char *pem_cert_chain_pathname,
                                          const char *pem_priv_key_pathname,
                                          const char *password)
{
    return (tls_credentials_t *) make_tls_credentials_2;
}

void destroy_tls_credentials(tls_credentials_t *credentials)
{
    CFRelease(credentials->cert_refs);
    fsfree(credentials);
}

static OSStatus _read_func(tls_conn_t *conn, void *data, size_t *dataLength)
{
    size_t size = *dataLength;
    if (!size)
        return errSecSuccess;
    if (size > INT_MAX)
        size = INT_MAX;
    ssize_t n = bytestream_1_read(conn->encrypted_input_stream, data, size);
    if (n < 0) {
        *dataLength = 0;
        if (errno == EAGAIN)
            return errSSLWouldBlock;
        return errSecIO;
    }
    if (n == 0)
        return errSSLClosedGraceful;
    tls_notify_application(conn);
    if (*dataLength == n)
        return errSecSuccess;
    *dataLength = n;
    return errSSLWouldBlock;
}

FSTRACE_DECL(ASYNCTLS_SECTRAN_READ_FUNC,
             "UID=%64u LENGTH=%z STATUS=%I PROCESSED=%z");
FSTRACE_DECL(ASYNCTLS_SECTRAN_READ_FUNC_DUMP, "UID=%64u DATA=%B");

static OSStatus read_func(SSLConnectionRef connection, void *data,
                          size_t *dataLength)
{
    tls_conn_t *conn = (tls_conn_t *) connection;
    size_t size = *dataLength;
    OSStatus status = _read_func(conn, data, dataLength);
    FSTRACE(ASYNCTLS_SECTRAN_READ_FUNC, conn->uid, size, trace_OSStatus,
            &status, *dataLength);
    FSTRACE(ASYNCTLS_SECTRAN_READ_FUNC_DUMP, conn->uid, data, *dataLength);
    return status;
}

static OSStatus _write_func(tls_conn_t *conn, const void *data,
                            size_t *dataLength)
{
    size_t size = *dataLength;
    if (!size)
        return errSecSuccess;
    buffer_t *buffer = &tech(conn)->encrypted_output_buffer;
    size_t space_left = buffer_space(buffer);
    if (size > space_left)
        size = space_left;
    if (!buffer_remaining(buffer))
        tls_notify_transport(conn);
    else if (!space_left) {
        *dataLength = 0;
        return errSSLWouldBlock;
    }
    buffer_fill(buffer, data, size);
    if (size == *dataLength)
        return errSecSuccess;
    *dataLength = size;
    return errSSLWouldBlock;
}

FSTRACE_DECL(ASYNCTLS_SECTRAN_WRITE_FUNC,
             "UID=%64u LENGTH=%z STATUS=%I PROCESSED=%z");
FSTRACE_DECL(ASYNCTLS_SECTRAN_WRITE_FUNC_DUMP, "UID=%64u DATA=%B");

static OSStatus write_func(SSLConnectionRef connection, const void *data,
                           size_t *dataLength)
{
    tls_conn_t *conn = (tls_conn_t *) connection;
    size_t size = *dataLength;
    OSStatus status = _write_func(conn, data, dataLength);
    FSTRACE(ASYNCTLS_SECTRAN_WRITE_FUNC, conn->uid, size, trace_OSStatus,
            &status, *dataLength);
    FSTRACE(ASYNCTLS_SECTRAN_WRITE_FUNC_DUMP, conn->uid, data, *dataLength);
    return status;
}

void tls_initialize_underlying_client_tech(tls_conn_t *conn)
{
    conn->underlying_tech = fsalloc(sizeof(secure_transport_tech_t));
    buffer_reset(&tech(conn)->encrypted_output_buffer);
    buffer_reset(&tech(conn)->plain_output_buffer);
    tech(conn)->ssl =
        SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    OSStatus status = SSLSetConnection(tech(conn)->ssl, conn);
    assert(status == errSecSuccess);
    status = SSLSetIOFuncs(tech(conn)->ssl, read_func, write_func);
    assert(status == errSecSuccess);
    status = SSLSetPeerDomainName(tech(conn)->ssl, conn->server_name,
                                  strlen(conn->server_name));
    assert(status == errSecSuccess);
    status = SSLSetProtocolVersionMin(tech(conn)->ssl, kTLSProtocol1);
    assert(status == errSecSuccess);
    /* TODO:
     * status = SSLSetCertificateAuthorities(tech(conn)->ssl,
     *                                       ...certificateOrArray, true);
     */
}

void tls_initialize_underlying_server_tech(tls_conn_t *conn)
{
    conn->underlying_tech = fsalloc(sizeof(secure_transport_tech_t));
    buffer_reset(&tech(conn)->encrypted_output_buffer);
    buffer_reset(&tech(conn)->plain_output_buffer);
    tech(conn)->ssl =
        SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
    OSStatus status = SSLSetConnection(tech(conn)->ssl, conn);
    assert(status == errSecSuccess);
    status = SSLSetIOFuncs(tech(conn)->ssl, read_func, write_func);
    assert(status == errSecSuccess);
    status = SSLSetProtocolVersionMin(tech(conn)->ssl, kTLSProtocol1);
    assert(status == errSecSuccess);
    status =
        SSLSetCertificate(tech(conn)->ssl, conn->server.credentials->cert_refs);
    assert(status == errSecSuccess);
}

void tls_adopt_tech(tls_conn_t *conn, void *_unused)
{
    assert(false);
}

void tls_free_underlying_resources(tls_conn_t *conn)
{
    CFRelease(tech(conn)->ssl);
    fsfree(tech(conn));
}

static const char *trace_OSStatus(void *status)
{
    switch (*(OSStatus *) status) {
        case 0:
            return "errSessionSuccess";
        case -60500:
            return "errSessionInvalidId";
        case -60501:
            return "errSessionInvalidAttributes";
        case -60502:
            return "errSessionAuthorizationDenied";
        case -60503:
            return "errSessionValueNotSet";
        case -60008:
            return "errSessionInternal";
        case -60011:
            return "errSessionInvalidFlags";
        case -60001:
            return "errAuthorizationInvalidSet";
        case -60002:
            return "errAuthorizationInvalidRef";
        case -60003:
            return "errAuthorizationInvalidTag";
        case -60004:
            return "errAuthorizationInvalidPointer";
        case -60005:
            return "errAuthorizationDenied";
        case -60006:
            return "errAuthorizationCanceled";
        case -60007:
            return "errAuthorizationInteractionNotAllowed";
        case -60009:
            return "errAuthorizationExternalizeNotAllowed";
        case -60010:
            return "errAuthorizationInternalizeNotAllowed";
        case -60031:
            return "errAuthorizationToolExecuteFailure";
        case -60032:
            return "errAuthorizationToolEnvironmentError";
        case -60033:
            return "errAuthorizationBadAddress";
        case -67072:
            return "errSecCSUnimplemented";
        case -67071:
            return "errSecCSInvalidObjectRef";
        case -67070:
            return "errSecCSInvalidFlags";
        case -67069:
            return "errSecCSObjectRequired";
        case -67068:
            return "errSecCSStaticCodeNotFound";
        case -67067:
            return "errSecCSUnsupportedGuestAttributes";
        case -67066:
            return "errSecCSInvalidAttributeValues";
        case -67065:
            return "errSecCSNoSuchCode";
        case -67064:
            return "errSecCSMultipleGuests";
        case -67063:
            return "errSecCSGuestInvalid";
        case -67062:
            return "errSecCSUnsigned";
        case -67061:
            return "errSecCSSignatureFailed";
        case -67060:
            return "errSecCSSignatureNotVerifiable";
        case -67059:
            return "errSecCSSignatureUnsupported";
        case -67058:
            return "errSecCSBadDictionaryFormat";
        case -67057:
            return "errSecCSResourcesNotSealed";
        case -67056:
            return "errSecCSResourcesNotFound";
        case -67055:
            return "errSecCSResourcesInvalid";
        case -67054:
            return "errSecCSBadResource";
        case -67053:
            return "errSecCSResourceRulesInvalid";
        case -67052:
            return "errSecCSReqInvalid";
        case -67051:
            return "errSecCSReqUnsupported";
        case -67050:
            return "errSecCSReqFailed";
        case -67049:
            return "errSecCSBadObjectFormat";
        case -67048:
            return "errSecCSInternalError";
        case -67047:
            return "errSecCSHostReject";
        case -67046:
            return "errSecCSNotAHost";
        case -67045:
            return "errSecCSSignatureInvalid";
        case -67044:
            return "errSecCSHostProtocolRelativePath";
        case -67043:
            return "errSecCSHostProtocolContradiction";
        case -67042:
            return "errSecCSHostProtocolDedicationError";
        case -67041:
            return "errSecCSHostProtocolNotProxy";
        case -67040:
            return "errSecCSHostProtocolStateError";
        case -67039:
            return "errSecCSHostProtocolUnrelated";
        case -67037:
            return "errSecCSNotSupported";
        case -67036:
            return "errSecCSCMSTooLarge";
        case -67035:
            return "errSecCSHostProtocolInvalidHash";
        case -67034:
            return "errSecCSStaticCodeChanged";
        case -67033:
            return "errSecCSDBDenied";
        case -67032:
            return "errSecCSDBAccess";
        case -67031:
            return "errSecCSHostProtocolInvalidAttribute";
        case -67030:
            return "errSecCSInfoPlistFailed";
        case -67029:
            return "errSecCSNoMainExecutable";
        case -67028:
            return "errSecCSBadBundleFormat";
        case -67027:
            return "errSecCSNoMatches";
        case -67026:
            return "errSecCSFileHardQuarantined";
        case -67025:
            return "errSecCSOutdated";
        case -67024:
            return "errSecCSDbCorrupt";
        case -67023:
            return "errSecCSResourceDirectoryFailed";
        case -67022:
            return "errSecCSUnsignedNestedCode";
        case -67021:
            return "errSecCSBadNestedCode";
        case -67020:
            return "errSecCSBadCallbackValue";
        case -67019:
            return "errSecCSHelperFailed";
        case -67018:
            return "errSecCSVetoed";
        case -67017:
            return "errSecCSBadLVArch";
        case -67016:
            return "errSecCSResourceNotSupported";
        case -67015:
            return "errSecCSRegularFile";
        case -67014:
            return "errSecCSUnsealedAppRoot";
        case -67013:
            return "errSecCSWeakResourceRules";
        case -67012:
            return "errSecCSDSStoreSymlink";
        case -67011:
            return "errSecCSAmbiguousBundleFormat";
        case -67010:
            return "errSecCSBadMainExecutable";
        case -67009:
            return "errSecCSBadFrameworkVersion";
        case -67008:
            return "errSecCSUnsealedFrameworkRoot";
        case -67007:
            return "errSecCSWeakResourceEnvelope";
        case -67006:
            return "errSecCSCancelled";
        case -67005:
            return "errSecCSInvalidPlatform";
        case -67004:
            return "errSecCSTooBig";
        case -67003:
            return "errSecCSInvalidSymlink";
        case -67002:
            return "errSecCSNotAppLike";
        case -67001:
            return "errSecCSBadDiskImageFormat";
        case -67000:
            return "errSecCSUnsupportedDigestAlgorithm";
        case -66999:
            return "errSecCSInvalidAssociatedFileData";
        case -66998:
            return "errSecCSInvalidTeamIdentifier";
        case -66997:
            return "errSecCSBadTeamIdentifier";
        case -66996:
            return "errSecCSSignatureUntrusted";
        case -66995:
            return "errSecMultipleExecSegments";
        case 32:
            return "kSecKeychainPromptUnsignedAct";
        case -4:
            return "errSecUnimplemented";
        case -34:
            return "errSecDskFull";
        case -36:
            return "errSecIO";
        case -49:
            return "errSecOpWr";
        case -50:
            return "errSecParam";
        case -61:
            return "errSecWrPerm";
        case -108:
            return "errSecAllocate";
        case -128:
            return "errSecUserCanceled";
        case -909:
            return "errSecBadReq";
        case -2070:
            return "errSecInternalComponent";
        case -4960:
            return "errSecCoreFoundationUnknown";
        case -34018:
            return "errSecMissingEntitlement";
        case -25291:
            return "errSecNotAvailable";
        case -25292:
            return "errSecReadOnly";
        case -25293:
            return "errSecAuthFailed";
        case -25294:
            return "errSecNoSuchKeychain";
        case -25295:
            return "errSecInvalidKeychain";
        case -25296:
            return "errSecDuplicateKeychain";
        case -25297:
            return "errSecDuplicateCallback";
        case -25298:
            return "errSecInvalidCallback";
        case -25299:
            return "errSecDuplicateItem";
        case -25300:
            return "errSecItemNotFound";
        case -25301:
            return "errSecBufferTooSmall";
        case -25302:
            return "errSecDataTooLarge";
        case -25303:
            return "errSecNoSuchAttr";
        case -25304:
            return "errSecInvalidItemRef";
        case -25305:
            return "errSecInvalidSearchRef";
        case -25306:
            return "errSecNoSuchClass";
        case -25307:
            return "errSecNoDefaultKeychain";
        case -25308:
            return "errSecInteractionNotAllowed";
        case -25309:
            return "errSecReadOnlyAttr";
        case -25310:
            return "errSecWrongSecVersion";
        case -25311:
            return "errSecKeySizeNotAllowed";
        case -25312:
            return "errSecNoStorageModule";
        case -25313:
            return "errSecNoCertificateModule";
        case -25314:
            return "errSecNoPolicyModule";
        case -25315:
            return "errSecInteractionRequired";
        case -25316:
            return "errSecDataNotAvailable";
        case -25317:
            return "errSecDataNotModifiable";
        case -25318:
            return "errSecCreateChainFailed";
        case -25319:
            return "errSecInvalidPrefsDomain";
        case -25320:
            return "errSecInDarkWake";
        case -25240:
            return "errSecACLNotSimple";
        case -25241:
            return "errSecPolicyNotFound";
        case -25242:
            return "errSecInvalidTrustSetting";
        case -25243:
            return "errSecNoAccessForItem";
        case -25244:
            return "errSecInvalidOwnerEdit";
        case -25245:
            return "errSecTrustNotAvailable";
        case -25256:
            return "errSecUnsupportedFormat";
        case -25257:
            return "errSecUnknownFormat";
        case -25258:
            return "errSecKeyIsSensitive";
        case -25259:
            return "errSecMultiplePrivKeys";
        case -25260:
            return "errSecPassphraseRequired";
        case -25261:
            return "errSecInvalidPasswordRef";
        case -25262:
            return "errSecInvalidTrustSettings";
        case -25263:
            return "errSecNoTrustSettings";
        case -25264:
            return "errSecPkcs12VerifyFailure";
        case -26267:
            return "errSecNotSigner";
        case -26275:
            return "errSecDecode";
        case -67585:
            return "errSecServiceNotAvailable";
        case -67586:
            return "errSecInsufficientClientID";
        case -67587:
            return "errSecDeviceReset";
        case -67588:
            return "errSecDeviceFailed";
        case -67589:
            return "errSecAppleAddAppACLSubject";
        case -67590:
            return "errSecApplePublicKeyIncomplete";
        case -67591:
            return "errSecAppleSignatureMismatch";
        case -67592:
            return "errSecAppleInvalidKeyStartDate";
        case -67593:
            return "errSecAppleInvalidKeyEndDate";
        case -67594:
            return "errSecConversionError";
        case -67595:
            return "errSecAppleSSLv2Rollback";
        case -67596:
            return "errSecQuotaExceeded";
        case -67597:
            return "errSecFileTooBig";
        case -67598:
            return "errSecInvalidDatabaseBlob";
        case -67599:
            return "errSecInvalidKeyBlob";
        case -67600:
            return "errSecIncompatibleDatabaseBlob";
        case -67601:
            return "errSecIncompatibleKeyBlob";
        case -67602:
            return "errSecHostNameMismatch";
        case -67603:
            return "errSecUnknownCriticalExtensionFlag";
        case -67604:
            return "errSecNoBasicConstraints";
        case -67605:
            return "errSecNoBasicConstraintsCA";
        case -67606:
            return "errSecInvalidAuthorityKeyID";
        case -67607:
            return "errSecInvalidSubjectKeyID";
        case -67608:
            return "errSecInvalidKeyUsageForPolicy";
        case -67609:
            return "errSecInvalidExtendedKeyUsage";
        case -67610:
            return "errSecInvalidIDLinkage";
        case -67611:
            return "errSecPathLengthConstraintExceeded";
        case -67612:
            return "errSecInvalidRoot";
        case -67613:
            return "errSecCRLExpired";
        case -67614:
            return "errSecCRLNotValidYet";
        case -67615:
            return "errSecCRLNotFound";
        case -67616:
            return "errSecCRLServerDown";
        case -67617:
            return "errSecCRLBadURI";
        case -67618:
            return "errSecUnknownCertExtension";
        case -67619:
            return "errSecUnknownCRLExtension";
        case -67620:
            return "errSecCRLNotTrusted";
        case -67621:
            return "errSecCRLPolicyFailed";
        case -67622:
            return "errSecIDPFailure";
        case -67623:
            return "errSecSMIMEEmailAddressesNotFound";
        case -67624:
            return "errSecSMIMEBadExtendedKeyUsage";
        case -67625:
            return "errSecSMIMEBadKeyUsage";
        case -67626:
            return "errSecSMIMEKeyUsageNotCritical";
        case -67627:
            return "errSecSMIMENoEmailAddress";
        case -67628:
            return "errSecSMIMESubjAltNameNotCritical";
        case -67629:
            return "errSecSSLBadExtendedKeyUsage";
        case -67630:
            return "errSecOCSPBadResponse";
        case -67631:
            return "errSecOCSPBadRequest";
        case -67632:
            return "errSecOCSPUnavailable";
        case -67633:
            return "errSecOCSPStatusUnrecognized";
        case -67634:
            return "errSecEndOfData";
        case -67635:
            return "errSecIncompleteCertRevocationCheck";
        case -67636:
            return "errSecNetworkFailure";
        case -67637:
            return "errSecOCSPNotTrustedToAnchor";
        case -67638:
            return "errSecRecordModified";
        case -67639:
            return "errSecOCSPSignatureError";
        case -67640:
            return "errSecOCSPNoSigner";
        case -67641:
            return "errSecOCSPResponderMalformedReq";
        case -67642:
            return "errSecOCSPResponderInternalError";
        case -67643:
            return "errSecOCSPResponderTryLater";
        case -67644:
            return "errSecOCSPResponderSignatureRequired";
        case -67645:
            return "errSecOCSPResponderUnauthorized";
        case -67646:
            return "errSecOCSPResponseNonceMismatch";
        case -67647:
            return "errSecCodeSigningBadCertChainLength";
        case -67648:
            return "errSecCodeSigningNoBasicConstraints";
        case -67649:
            return "errSecCodeSigningBadPathLengthConstraint";
        case -67650:
            return "errSecCodeSigningNoExtendedKeyUsage";
        case -67651:
            return "errSecCodeSigningDevelopment";
        case -67652:
            return "errSecResourceSignBadCertChainLength";
        case -67653:
            return "errSecResourceSignBadExtKeyUsage";
        case -67654:
            return "errSecTrustSettingDeny";
        case -67655:
            return "errSecInvalidSubjectName";
        case -67656:
            return "errSecUnknownQualifiedCertStatement";
        case -67657:
            return "errSecMobileMeRequestQueued";
        case -67658:
            return "errSecMobileMeRequestRedirected";
        case -67659:
            return "errSecMobileMeServerError";
        case -67660:
            return "errSecMobileMeServerNotAvailable";
        case -67661:
            return "errSecMobileMeServerAlreadyExists";
        case -67662:
            return "errSecMobileMeServerServiceErr";
        case -67663:
            return "errSecMobileMeRequestAlreadyPending";
        case -67664:
            return "errSecMobileMeNoRequestPending";
        case -67665:
            return "errSecMobileMeCSRVerifyFailure";
        case -67666:
            return "errSecMobileMeFailedConsistencyCheck";
        case -67667:
            return "errSecNotInitialized";
        case -67668:
            return "errSecInvalidHandleUsage";
        case -67669:
            return "errSecPVCReferentNotFound";
        case -67670:
            return "errSecFunctionIntegrityFail";
        case -67671:
            return "errSecInternalError";
        case -67672:
            return "errSecMemoryError";
        case -67673:
            return "errSecInvalidData";
        case -67674:
            return "errSecMDSError";
        case -67675:
            return "errSecInvalidPointer";
        case -67676:
            return "errSecSelfCheckFailed";
        case -67677:
            return "errSecFunctionFailed";
        case -67678:
            return "errSecModuleManifestVerifyFailed";
        case -67679:
            return "errSecInvalidGUID";
        case -67680:
            return "errSecInvalidHandle";
        case -67681:
            return "errSecInvalidDBList";
        case -67682:
            return "errSecInvalidPassthroughID";
        case -67683:
            return "errSecInvalidNetworkAddress";
        case -67684:
            return "errSecCRLAlreadySigned";
        case -67685:
            return "errSecInvalidNumberOfFields";
        case -67686:
            return "errSecVerificationFailure";
        case -67687:
            return "errSecUnknownTag";
        case -67688:
            return "errSecInvalidSignature";
        case -67689:
            return "errSecInvalidName";
        case -67690:
            return "errSecInvalidCertificateRef";
        case -67691:
            return "errSecInvalidCertificateGroup";
        case -67692:
            return "errSecTagNotFound";
        case -67693:
            return "errSecInvalidQuery";
        case -67694:
            return "errSecInvalidValue";
        case -67695:
            return "errSecCallbackFailed";
        case -67696:
            return "errSecACLDeleteFailed";
        case -67697:
            return "errSecACLReplaceFailed";
        case -67698:
            return "errSecACLAddFailed";
        case -67699:
            return "errSecACLChangeFailed";
        case -67700:
            return "errSecInvalidAccessCredentials";
        case -67701:
            return "errSecInvalidRecord";
        case -67702:
            return "errSecInvalidACL";
        case -67703:
            return "errSecInvalidSampleValue";
        case -67704:
            return "errSecIncompatibleVersion";
        case -67705:
            return "errSecPrivilegeNotGranted";
        case -67706:
            return "errSecInvalidScope";
        case -67707:
            return "errSecPVCAlreadyConfigured";
        case -67708:
            return "errSecInvalidPVC";
        case -67709:
            return "errSecEMMLoadFailed";
        case -67710:
            return "errSecEMMUnloadFailed";
        case -67711:
            return "errSecAddinLoadFailed";
        case -67712:
            return "errSecInvalidKeyRef";
        case -67713:
            return "errSecInvalidKeyHierarchy";
        case -67714:
            return "errSecAddinUnloadFailed";
        case -67715:
            return "errSecLibraryReferenceNotFound";
        case -67716:
            return "errSecInvalidAddinFunctionTable";
        case -67717:
            return "errSecInvalidServiceMask";
        case -67718:
            return "errSecModuleNotLoaded";
        case -67719:
            return "errSecInvalidSubServiceID";
        case -67720:
            return "errSecAttributeNotInContext";
        case -67721:
            return "errSecModuleManagerInitializeFailed";
        case -67722:
            return "errSecModuleManagerNotFound";
        case -67723:
            return "errSecEventNotificationCallbackNotFound";
        case -67724:
            return "errSecInputLengthError";
        case -67725:
            return "errSecOutputLengthError";
        case -67726:
            return "errSecPrivilegeNotSupported";
        case -67727:
            return "errSecDeviceError";
        case -67728:
            return "errSecAttachHandleBusy";
        case -67729:
            return "errSecNotLoggedIn";
        case -67730:
            return "errSecAlgorithmMismatch";
        case -67731:
            return "errSecKeyUsageIncorrect";
        case -67732:
            return "errSecKeyBlobTypeIncorrect";
        case -67733:
            return "errSecKeyHeaderInconsistent";
        case -67734:
            return "errSecUnsupportedKeyFormat";
        case -67735:
            return "errSecUnsupportedKeySize";
        case -67736:
            return "errSecInvalidKeyUsageMask";
        case -67737:
            return "errSecUnsupportedKeyUsageMask";
        case -67738:
            return "errSecInvalidKeyAttributeMask";
        case -67739:
            return "errSecUnsupportedKeyAttributeMask";
        case -67740:
            return "errSecInvalidKeyLabel";
        case -67741:
            return "errSecUnsupportedKeyLabel";
        case -67742:
            return "errSecInvalidKeyFormat";
        case -67743:
            return "errSecUnsupportedVectorOfBuffers";
        case -67744:
            return "errSecInvalidInputVector";
        case -67745:
            return "errSecInvalidOutputVector";
        case -67746:
            return "errSecInvalidContext";
        case -67747:
            return "errSecInvalidAlgorithm";
        case -67748:
            return "errSecInvalidAttributeKey";
        case -67749:
            return "errSecMissingAttributeKey";
        case -67750:
            return "errSecInvalidAttributeInitVector";
        case -67751:
            return "errSecMissingAttributeInitVector";
        case -67752:
            return "errSecInvalidAttributeSalt";
        case -67753:
            return "errSecMissingAttributeSalt";
        case -67754:
            return "errSecInvalidAttributePadding";
        case -67755:
            return "errSecMissingAttributePadding";
        case -67756:
            return "errSecInvalidAttributeRandom";
        case -67757:
            return "errSecMissingAttributeRandom";
        case -67758:
            return "errSecInvalidAttributeSeed";
        case -67759:
            return "errSecMissingAttributeSeed";
        case -67760:
            return "errSecInvalidAttributePassphrase";
        case -67761:
            return "errSecMissingAttributePassphrase";
        case -67762:
            return "errSecInvalidAttributeKeyLength";
        case -67763:
            return "errSecMissingAttributeKeyLength";
        case -67764:
            return "errSecInvalidAttributeBlockSize";
        case -67765:
            return "errSecMissingAttributeBlockSize";
        case -67766:
            return "errSecInvalidAttributeOutputSize";
        case -67767:
            return "errSecMissingAttributeOutputSize";
        case -67768:
            return "errSecInvalidAttributeRounds";
        case -67769:
            return "errSecMissingAttributeRounds";
        case -67770:
            return "errSecInvalidAlgorithmParms";
        case -67771:
            return "errSecMissingAlgorithmParms";
        case -67772:
            return "errSecInvalidAttributeLabel";
        case -67773:
            return "errSecMissingAttributeLabel";
        case -67774:
            return "errSecInvalidAttributeKeyType";
        case -67775:
            return "errSecMissingAttributeKeyType";
        case -67776:
            return "errSecInvalidAttributeMode";
        case -67777:
            return "errSecMissingAttributeMode";
        case -67778:
            return "errSecInvalidAttributeEffectiveBits";
        case -67779:
            return "errSecMissingAttributeEffectiveBits";
        case -67780:
            return "errSecInvalidAttributeStartDate";
        case -67781:
            return "errSecMissingAttributeStartDate";
        case -67782:
            return "errSecInvalidAttributeEndDate";
        case -67783:
            return "errSecMissingAttributeEndDate";
        case -67784:
            return "errSecInvalidAttributeVersion";
        case -67785:
            return "errSecMissingAttributeVersion";
        case -67786:
            return "errSecInvalidAttributePrime";
        case -67787:
            return "errSecMissingAttributePrime";
        case -67788:
            return "errSecInvalidAttributeBase";
        case -67789:
            return "errSecMissingAttributeBase";
        case -67790:
            return "errSecInvalidAttributeSubprime";
        case -67791:
            return "errSecMissingAttributeSubprime";
        case -67792:
            return "errSecInvalidAttributeIterationCount";
        case -67793:
            return "errSecMissingAttributeIterationCount";
        case -67794:
            return "errSecInvalidAttributeDLDBHandle";
        case -67795:
            return "errSecMissingAttributeDLDBHandle";
        case -67796:
            return "errSecInvalidAttributeAccessCredentials";
        case -67797:
            return "errSecMissingAttributeAccessCredentials";
        case -67798:
            return "errSecInvalidAttributePublicKeyFormat";
        case -67799:
            return "errSecMissingAttributePublicKeyFormat";
        case -67800:
            return "errSecInvalidAttributePrivateKeyFormat";
        case -67801:
            return "errSecMissingAttributePrivateKeyFormat";
        case -67802:
            return "errSecInvalidAttributeSymmetricKeyFormat";
        case -67803:
            return "errSecMissingAttributeSymmetricKeyFormat";
        case -67804:
            return "errSecInvalidAttributeWrappedKeyFormat";
        case -67805:
            return "errSecMissingAttributeWrappedKeyFormat";
        case -67806:
            return "errSecStagedOperationInProgress";
        case -67807:
            return "errSecStagedOperationNotStarted";
        case -67808:
            return "errSecVerifyFailed";
        case -67809:
            return "errSecQuerySizeUnknown";
        case -67810:
            return "errSecBlockSizeMismatch";
        case -67811:
            return "errSecPublicKeyInconsistent";
        case -67812:
            return "errSecDeviceVerifyFailed";
        case -67813:
            return "errSecInvalidLoginName";
        case -67814:
            return "errSecAlreadyLoggedIn";
        case -67815:
            return "errSecInvalidDigestAlgorithm";
        case -67816:
            return "errSecInvalidCRLGroup";
        case -67817:
            return "errSecCertificateCannotOperate";
        case -67818:
            return "errSecCertificateExpired";
        case -67819:
            return "errSecCertificateNotValidYet";
        case -67820:
            return "errSecCertificateRevoked";
        case -67821:
            return "errSecCertificateSuspended";
        case -67822:
            return "errSecInsufficientCredentials";
        case -67823:
            return "errSecInvalidAction";
        case -67824:
            return "errSecInvalidAuthority";
        case -67825:
            return "errSecVerifyActionFailed";
        case -67826:
            return "errSecInvalidCertAuthority";
        case -67827:
            return "errSecInvaldCRLAuthority";
        case -67828:
            return "errSecInvalidCRLEncoding";
        case -67829:
            return "errSecInvalidCRLType";
        case -67830:
            return "errSecInvalidCRL";
        case -67831:
            return "errSecInvalidFormType";
        case -67832:
            return "errSecInvalidID";
        case -67833:
            return "errSecInvalidIdentifier";
        case -67834:
            return "errSecInvalidIndex";
        case -67835:
            return "errSecInvalidPolicyIdentifiers";
        case -67836:
            return "errSecInvalidTimeString";
        case -67837:
            return "errSecInvalidReason";
        case -67838:
            return "errSecInvalidRequestInputs";
        case -67839:
            return "errSecInvalidResponseVector";
        case -67840:
            return "errSecInvalidStopOnPolicy";
        case -67841:
            return "errSecInvalidTuple";
        case -67842:
            return "errSecMultipleValuesUnsupported";
        case -67843:
            return "errSecNotTrusted";
        case -67844:
            return "errSecNoDefaultAuthority";
        case -67845:
            return "errSecRejectedForm";
        case -67846:
            return "errSecRequestLost";
        case -67847:
            return "errSecRequestRejected";
        case -67848:
            return "errSecUnsupportedAddressType";
        case -67849:
            return "errSecUnsupportedService";
        case -67850:
            return "errSecInvalidTupleGroup";
        case -67851:
            return "errSecInvalidBaseACLs";
        case -67852:
            return "errSecInvalidTupleCredendtials";
        case -67853:
            return "errSecInvalidEncoding";
        case -67854:
            return "errSecInvalidValidityPeriod";
        case -67855:
            return "errSecInvalidRequestor";
        case -67856:
            return "errSecRequestDescriptor";
        case -67857:
            return "errSecInvalidBundleInfo";
        case -67858:
            return "errSecInvalidCRLIndex";
        case -67859:
            return "errSecNoFieldValues";
        case -67860:
            return "errSecUnsupportedFieldFormat";
        case -67861:
            return "errSecUnsupportedIndexInfo";
        case -67862:
            return "errSecUnsupportedLocality";
        case -67863:
            return "errSecUnsupportedNumAttributes";
        case -67864:
            return "errSecUnsupportedNumIndexes";
        case -67865:
            return "errSecUnsupportedNumRecordTypes";
        case -67866:
            return "errSecFieldSpecifiedMultiple";
        case -67867:
            return "errSecIncompatibleFieldFormat";
        case -67868:
            return "errSecInvalidParsingModule";
        case -67869:
            return "errSecDatabaseLocked";
        case -67870:
            return "errSecDatastoreIsOpen";
        case -67871:
            return "errSecMissingValue";
        case -67872:
            return "errSecUnsupportedQueryLimits";
        case -67873:
            return "errSecUnsupportedNumSelectionPreds";
        case -67874:
            return "errSecUnsupportedOperator";
        case -67875:
            return "errSecInvalidDBLocation";
        case -67876:
            return "errSecInvalidAccessRequest";
        case -67877:
            return "errSecInvalidIndexInfo";
        case -67878:
            return "errSecInvalidNewOwner";
        case -67879:
            return "errSecInvalidModifyMode";
        case -67880:
            return "errSecMissingRequiredExtension";
        case -67881:
            return "errSecExtendedKeyUsageNotCritical";
        case -67882:
            return "errSecTimestampMissing";
        case -67883:
            return "errSecTimestampInvalid";
        case -67884:
            return "errSecTimestampNotTrusted";
        case -67885:
            return "errSecTimestampServiceNotAvailable";
        case -67886:
            return "errSecTimestampBadAlg";
        case -67887:
            return "errSecTimestampBadRequest";
        case -67888:
            return "errSecTimestampBadDataFormat";
        case -67889:
            return "errSecTimestampTimeNotAvailable";
        case -67890:
            return "errSecTimestampUnacceptedPolicy";
        case -67891:
            return "errSecTimestampUnacceptedExtension";
        case -67892:
            return "errSecTimestampAddInfoNotAvailable";
        case -67893:
            return "errSecTimestampSystemFailure";
        case -67894:
            return "errSecSigningTimeMissing";
        case -67895:
            return "errSecTimestampRejection";
        case -67896:
            return "errSecTimestampWaiting";
        case -67897:
            return "errSecTimestampRevocationWarning";
        case -67898:
            return "errSecTimestampRevocationNotification";
        case -9800:
            return "errSSLProtocol";
        case -9801:
            return "errSSLNegotiation";
        case -9802:
            return "errSSLFatalAlert";
        case -9803:
            return "errSSLWouldBlock";
        case -9804:
            return "errSSLSessionNotFound";
        case -9805:
            return "errSSLClosedGraceful";
        case -9806:
            return "errSSLClosedAbort";
        case -9807:
            return "errSSLXCertChainInvalid";
        case -9808:
            return "errSSLBadCert";
        case -9809:
            return "errSSLCrypto";
        case -9810:
            return "errSSLInternal";
        case -9811:
            return "errSSLModuleAttach";
        case -9812:
            return "errSSLUnknownRootCert";
        case -9813:
            return "errSSLNoRootCert";
        case -9814:
            return "errSSLCertExpired";
        case -9815:
            return "errSSLCertNotYetValid";
        case -9816:
            return "errSSLClosedNoNotify";
        case -9817:
            return "errSSLBufferOverflow";
        case -9818:
            return "errSSLBadCipherSuite";
        case -9819:
            return "errSSLPeerUnexpectedMsg";
        case -9820:
            return "errSSLPeerBadRecordMac";
        case -9821:
            return "errSSLPeerDecryptionFail";
        case -9822:
            return "errSSLPeerRecordOverflow";
        case -9823:
            return "errSSLPeerDecompressFail";
        case -9824:
            return "errSSLPeerHandshakeFail";
        case -9825:
            return "errSSLPeerBadCert";
        case -9826:
            return "errSSLPeerUnsupportedCert";
        case -9827:
            return "errSSLPeerCertRevoked";
        case -9828:
            return "errSSLPeerCertExpired";
        case -9829:
            return "errSSLPeerCertUnknown";
        case -9830:
            return "errSSLIllegalParam";
        case -9831:
            return "errSSLPeerUnknownCA";
        case -9832:
            return "errSSLPeerAccessDenied";
        case -9833:
            return "errSSLPeerDecodeError";
        case -9834:
            return "errSSLPeerDecryptError";
        case -9835:
            return "errSSLPeerExportRestriction";
        case -9836:
            return "errSSLPeerProtocolVersion";
        case -9837:
            return "errSSLPeerInsufficientSecurity";
        case -9838:
            return "errSSLPeerInternalError";
        case -9839:
            return "errSSLPeerUserCancelled";
        case -9840:
            return "errSSLPeerNoRenegotiation";
        case -9841:
            return "errSSLPeerAuthCompleted";
        case -9842:
            return "errSSLClientCertRequested";
        case -9843:
            return "errSSLHostNameMismatch";
        case -9844:
            return "errSSLConnectionRefused";
        case -9845:
            return "errSSLDecryptionFail";
        case -9846:
            return "errSSLBadRecordMac";
        case -9847:
            return "errSSLRecordOverflow";
        case -9848:
            return "errSSLBadConfiguration";
        case -9849:
            return "errSSLUnexpectedRecord";
        case -9850:
            return "errSSLWeakPeerEphemeralDHKey";
        case -9851:
            return "errSSLClientHelloReceived";
        default: {
            static char buf[20];
            sprintf(buf, "%d", (int) *(OSStatus *) status);
            return buf;
        }
    }
}
