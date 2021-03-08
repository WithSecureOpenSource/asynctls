#include <errno.h>
#include <assert.h>
#include <fstrace.h>
#include <fsdyn/fsalloc.h>
#include <async/drystream.h>
#include <async/errorstream.h>
#include <async/blobstream.h>
#include "tls_underlying.h"
#include "asynctls_version.h"

static ssize_t read_plain_input(tls_conn_t *conn, void *buf, size_t count);

static const char *trace_state(void *pstate)
{
    switch (*(tls_conn_state_t *) pstate) {
        case TLS_CONN_STATE_HANDSHAKING:
            return "TLS_CONN_STATE_HANDSHAKING";
        case TLS_CONN_STATE_OPEN:
            return "TLS_CONN_STATE_OPEN";
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            return "TLS_CONN_STATE_SHUT_DOWN_OUTGOING";
        case TLS_CONN_STATE_DENIED:
            return "TLS_CONN_STATE_DENIED";
        case TLS_CONN_STATE_ERRORED:
            return "TLS_CONN_STATE_ERRORED";
        case TLS_CONN_STATE_ZOMBIE:
            return "TLS_CONN_STATE_ZOMBIE";
        default:
            return "?";
    }
}

FSTRACE_DECL(ASYNCTLS_CONN_SET_STATE, "UID=%64u OLD=%I NEW=%I")

void tls_set_conn_state(tls_conn_t *conn, tls_conn_state_t state)
{
    FSTRACE(ASYNCTLS_CONN_SET_STATE, conn->uid,
            trace_state, &conn->state, trace_state, &state);
    conn->state = state;
}

FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT_IGNORED, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT_SPURIOUS, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT_UNEXPECTED, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT_FAIL, "UID=%64u ERRNO=%e")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_INPUT_EOF, "UID=%64u")

static void input_notification(tls_conn_t *conn)
{
    if (conn->state == TLS_CONN_STATE_ZOMBIE) {
        FSTRACE(ASYNCTLS_CONN_CHECK_INPUT_IGNORED, conn->uid);
        return;
    }
    if (!conn->plain_input_closed) {
        FSTRACE(ASYNCTLS_CONN_CHECK_INPUT, conn->uid);
        action_1_perf(conn->plain_input_callback);
        return;
    }
    char c;
    ssize_t n = read_plain_input(conn, &c, 1);
    if (n == 0) {
        FSTRACE(ASYNCTLS_CONN_CHECK_INPUT_EOF, conn->uid);
        return;
    }
    if (n > 0) {
        FSTRACE(ASYNCTLS_CONN_CHECK_INPUT_UNEXPECTED, conn->uid);
        tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
        return;
    }
    if (errno == EAGAIN) {
        FSTRACE(ASYNCTLS_CONN_CHECK_INPUT_SPURIOUS, conn->uid);
        return;
    }
    FSTRACE(ASYNCTLS_CONN_CHECK_INPUT_FAIL, conn->uid);
    tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
}

FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT_IGNORED, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT_SPURIOUS, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT_UNEXPECTED, "UID=%64u")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT_FAIL, "UID=%64u ERRNO=%e")
FSTRACE_DECL(ASYNCTLS_CONN_CHECK_OUTPUT_EOF, "UID=%64u")

static void output_notification(tls_conn_t *conn)
{
    if (conn->state == TLS_CONN_STATE_ZOMBIE) {
        FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT_IGNORED, conn->uid);
        return;
    }
    if (!conn->encrypted_output_closed) {
        FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT, conn->uid);
        action_1_perf(conn->encrypted_output_callback);
        return;
    }
    char c;
    ssize_t n = tls_read_encrypted_output(conn, &c, 1);
    if (n == 0) {
        FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT_EOF, conn->uid);
        return;
    }
    if (n > 0) {
        FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT_UNEXPECTED, conn->uid);
        tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
        return;
    }
    if (errno == EAGAIN) {
        FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT_SPURIOUS, conn->uid);
        return;
    }
    FSTRACE(ASYNCTLS_CONN_CHECK_OUTPUT_FAIL, conn->uid);
    tls_set_conn_state(conn, TLS_CONN_STATE_ERRORED);
}

FSTRACE_DECL(ASYNCTLS_CONN_NOTIFY_TRANSPORT, "UID=%64u");

void tls_notify_transport(tls_conn_t *conn)
{
    FSTRACE(ASYNCTLS_CONN_NOTIFY_TRANSPORT, conn->uid);
    action_1 notif = { conn, (act_1) output_notification };
    async_execute(conn->async, notif);
}

static ssize_t read_plain_input(tls_conn_t *conn, void *buf, size_t count)
{
    switch (conn->state) {
        case TLS_CONN_STATE_HANDSHAKING:
            if (tls_perform_handshake(conn) < 0)
                return -1;
            if (count == 0)
                return 0;
            return tls_read_plain_input(conn, buf, count);
        case TLS_CONN_STATE_OPEN:
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            if (count == 0)
                return 0;
            return tls_read_plain_input(conn, buf, count);
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

FSTRACE_DECL(ASYNCTLS_CONN_PLAIN_INPUT_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCTLS_CONN_PLAIN_INPUT_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t plain_input_stream_read(void *obj, void *buf, size_t count)
{
    tls_conn_t *conn = obj;
    assert(!conn->plain_input_closed);
    ssize_t n = read_plain_input(conn, buf, count);
    FSTRACE(ASYNCTLS_CONN_PLAIN_INPUT_READ, conn->uid, count, n);
    FSTRACE(ASYNCTLS_CONN_PLAIN_INPUT_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCTLS_CONN_PLAIN_INPUT_CLOSE, "UID=%64u");

static void plain_input_stream_close(void *obj)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_PLAIN_INPUT_CLOSE, conn->uid);
    if (conn->state == TLS_CONN_STATE_ZOMBIE)
        return;
    conn->plain_input_closed = true;
}

FSTRACE_DECL(ASYNCTLS_CONN_PLAIN_INPUT_REGISTER, "UID=%64u OBJ=%p ACT=%p");

static void plain_input_stream_register_callback(void *obj, action_1 action)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_PLAIN_INPUT_REGISTER,
            conn->uid, action.obj, action.act);
    conn->plain_input_callback = action;
}

FSTRACE_DECL(ASYNCTLS_CONN_PLAIN_INPUT_UNREGISTER, "UID=%64u");

static void plain_input_stream_unregister_callback(void *obj)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_PLAIN_INPUT_UNREGISTER, conn->uid);
    conn->plain_input_callback = NULL_ACTION_1;
    bytestream_1_unregister_callback(conn->encrypted_input_stream);
}

static const struct bytestream_1_vt plain_input_stream_vt = {
    .read = plain_input_stream_read,
    .close = plain_input_stream_close,
    .register_callback = plain_input_stream_register_callback,
    .unregister_callback = plain_input_stream_unregister_callback
};

FSTRACE_DECL(ASYNCTLS_CONN_NOTIFY_APPLICATION, "UID=%64u");

void tls_notify_application(tls_conn_t *conn)
{
    FSTRACE(ASYNCTLS_CONN_NOTIFY_APPLICATION, conn->uid);
    action_1 notif = { conn, (act_1) input_notification };
    async_execute(conn->async, notif);
}

FSTRACE_DECL(ASYNCTLS_CONN_SET_ALPN, "UID=%64u PROTO=%s");

void tls_set_alpn_choice(tls_conn_t *conn, char *protocol)
{
    FSTRACE(ASYNCTLS_CONN_SET_ALPN, conn->uid, protocol);
    assert(!conn->alpn_choice);
    conn->alpn_choice = protocol;
}

const char *tls_get_chosen_protocol(tls_conn_t *conn)
{
    return conn->alpn_choice;
}

FSTRACE_DECL(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_READ,
             "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_READ_DUMP, "UID=%64u DATA=%B");

static ssize_t encrypted_output_stream_read(void *obj, void *buf, size_t count)
{
    tls_conn_t *conn = obj;
    if (conn->state == TLS_CONN_STATE_ZOMBIE) {
        errno = EBADF;
        return -1;
    }
    assert(!conn->encrypted_output_closed);
    ssize_t n = tls_read_encrypted_output(conn, buf, count);
    FSTRACE(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_READ, conn->uid, count, n);
    FSTRACE(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_CLOSE, "UID=%64u");

static void encrypted_output_stream_close(void *obj)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_CLOSE, conn->uid);
    assert(!conn->encrypted_output_closed);
    conn->encrypted_output_closed = true;
    if (conn->state == TLS_CONN_STATE_ZOMBIE)
        async_wound(conn->async, conn);
}

FSTRACE_DECL(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_REGISTER,
             "UID=%64u OBJ=%p ACT=%p");

static void encrypted_output_stream_register_callback(void *obj,
                                                      action_1 action)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_REGISTER,
            conn->uid, action.obj, action.act);
    conn->encrypted_output_callback = action;
    bytestream_1_register_callback(conn->plain_output_stream, action);
}

FSTRACE_DECL(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_UNREGISTER, "UID=%64u");

static void encrypted_output_stream_unregister_callback(void *obj)
{
    tls_conn_t *conn = obj;
    FSTRACE(ASYNCTLS_CONN_ENCRYPTED_OUTPUT_UNREGISTER, conn->uid);
    conn->encrypted_output_callback = NULL_ACTION_1;
    bytestream_1_unregister_callback(conn->plain_output_stream);
}

static const struct bytestream_1_vt encrypted_output_stream_vt = {
    .read = encrypted_output_stream_read,
    .close = encrypted_output_stream_close,
    .register_callback = encrypted_output_stream_register_callback,
    .unregister_callback = encrypted_output_stream_unregister_callback
};

static tls_conn_t *open_connection(async_t *async,
                                   bytestream_1 encrypted_input_stream)
{
    tls_conn_t *conn = fsalloc(sizeof *conn);
    conn->async = async;
    conn->uid = fstrace_get_unique_id();
    conn->encrypted_input_stream = encrypted_input_stream;
    conn->plain_output_stream = drystream;
    conn->plain_input_callback = NULL_ACTION_1;
    conn->handshake_done_callback = NULL_ACTION_1;
    action_1 encrypted_input_cb = { conn, (act_1) input_notification };
    bytestream_1_register_callback(encrypted_input_stream,
                                   encrypted_input_cb );
    conn->encrypted_output_callback = NULL_ACTION_1;
    conn->encrypted_output_closed = false;
    conn->plain_input_closed = false;
    return conn;
}

static tls_conn_t *make_client(async_t *async,
                               bytestream_1 encrypted_input_stream,
                               tls_ca_bundle_t *ca_bundle,
                               const char *server_hostname)
{
    tls_conn_t *conn = open_connection(async, encrypted_input_stream);
    conn->server_name = server_hostname;
    conn->is_client = true;
    conn->client.ca_bundle = ca_bundle;
    conn->alpn_choice = NULL;
    return conn;
}

static tls_conn_t *open_client(async_t *async,
                               bytestream_1 encrypted_input_stream,
                               tls_ca_bundle_t *ca_bundle,
                               const char *server_hostname)
{
    tls_conn_t *conn = make_client(async, encrypted_input_stream,
                                   ca_bundle, server_hostname);
    tls_initialize_underlying_client_tech(conn);
    conn->state = TLS_CONN_STATE_HANDSHAKING;
    return conn;
}

FSTRACE_DECL(ASYNCTLS_CONN_CLIENT_ADOPT,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p BUNDLE=%p UNDERLYING=%p");

tls_conn_t *adopt_tls_client(async_t *async,
                             bytestream_1 encrypted_input_stream,
                             tls_ca_bundle_t *ca_bundle,
                             void *underlying_connection)
{
    tls_conn_t *conn = make_client(async, encrypted_input_stream,
                                   share_tls_ca_bundle(ca_bundle), NULL);
    FSTRACE(ASYNCTLS_CONN_CLIENT_ADOPT, conn->uid, conn, async,
            encrypted_input_stream.obj, ca_bundle, underlying_connection);
    tls_adopt_tech(conn, underlying_connection);
    conn->state = TLS_CONN_STATE_OPEN;
    return conn;
}

FSTRACE_DECL(ASYNCTLS_CONN_CLIENT_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p FILE=%s DIR=%s SERVER=%s");

tls_conn_t *open_tls_client(async_t *async,
                            bytestream_1 encrypted_input_stream,
                            const char *pem_file_pathname,
                            const char *pem_dir_pathname,
                            const char *server_hostname)
{
    tls_conn_t *conn =
        open_client(async, encrypted_input_stream,
                    make_tls_ca_bundle(pem_file_pathname, pem_dir_pathname),
                    server_hostname);
    FSTRACE(ASYNCTLS_CONN_CLIENT_CREATE, conn->uid, conn, async,
            encrypted_input_stream.obj,
            pem_file_pathname, pem_dir_pathname, server_hostname);
    return conn;
}

FSTRACE_DECL(ASYNCTLS_CONN_CLIENT_CREATE2,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p CA-BUNDLE=%p SERVER=%s");

tls_conn_t *open_tls_client_2(async_t *async,
                              bytestream_1 encrypted_input_stream,
                              tls_ca_bundle_t *ca_bundle,
                              const char *server_hostname)
{
    tls_conn_t *conn =
        open_client(async, encrypted_input_stream,
                    share_tls_ca_bundle(ca_bundle), server_hostname);
    FSTRACE(ASYNCTLS_CONN_CLIENT_CREATE2, conn->uid, conn, async,
            encrypted_input_stream.obj, ca_bundle, server_hostname);
    return conn;
}

static tls_conn_t *open_server(async_t *async,
                               bytestream_1 encrypted_input_stream,
                               bool shared,
                               tls_credentials_t *credentials)
{
    tls_conn_t *conn = open_connection(async, encrypted_input_stream);
    conn->server_name = NULL;
    conn->is_client = false;
    conn->server.credentials_shared = shared;
    conn->server.credentials = credentials;
    conn->alpn_choice = NULL;
    tls_initialize_underlying_server_tech(conn);
    conn->state = TLS_CONN_STATE_HANDSHAKING;
    return conn;
}

tls_conn_t *adopt_tls_server(async_t *async,
                             bytestream_1 encrypted_input_stream,
                             tls_credentials_t *credentials,
                             void *underlying_connection)
{
    tls_conn_t *conn = open_connection(async, encrypted_input_stream);
    conn->server_name = NULL;
    conn->is_client = false;
    conn->server.credentials_shared = false;
    conn->server.credentials = credentials;
    tls_adopt_tech(conn, underlying_connection);
    conn->state = TLS_CONN_STATE_OPEN;
    return conn;
}

FSTRACE_DECL(ASYNCTLS_CONN_SERVER_CREATE,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p FILE=%s DIR=%s");

tls_conn_t *open_tls_server(async_t *async,
                            bytestream_1 encrypted_input_stream,
                            const char *pem_cert_chain_pathname,
                            const char *pem_dir_pathname)
{
    tls_credentials_t *credentials =
        make_tls_credentials(pem_cert_chain_pathname, pem_dir_pathname);
    if (!credentials)
        return NULL;
    tls_conn_t *conn =
        open_server(async, encrypted_input_stream, false, credentials);
    FSTRACE(ASYNCTLS_CONN_SERVER_CREATE, conn->uid, conn, async,
            encrypted_input_stream.obj,
            pem_cert_chain_pathname, pem_dir_pathname);
    return conn;
}

FSTRACE_DECL(ASYNCTLS_CONN_SERVER_CREATE2,
             "UID=%64u PTR=%p ASYNC=%p INPUT=%p CRED=%p");

tls_conn_t *open_tls_server_2(async_t *async,
                              bytestream_1 encrypted_input_stream,
                              tls_credentials_t *credentials)
{
    tls_conn_t *conn = open_server(async, encrypted_input_stream, true,
                                   credentials);
    FSTRACE(ASYNCTLS_CONN_SERVER_CREATE2, conn->uid, conn, async,
            encrypted_input_stream.obj, credentials);
    return conn;
}

bytestream_1 tls_get_encrypted_output_stream(tls_conn_t *conn)
{
    return (bytestream_1) { conn, &encrypted_output_stream_vt };
}

bytestream_1 tls_get_plain_input_stream(tls_conn_t *conn)
{
    return (bytestream_1) { conn, &plain_input_stream_vt };
}

FSTRACE_DECL(ASYNCTLS_CONN_READ, "UID=%64u WANT=%z GOT=%z ERRNO=%e");
FSTRACE_DECL(ASYNCTLS_CONN_READ_DUMP, "UID=%64u DATA=%B");

ssize_t tls_read(tls_conn_t *conn, void *buf, size_t count)
{
    ssize_t n =
        bytestream_1_read(tls_get_plain_input_stream(conn), buf, count);
    FSTRACE(ASYNCTLS_CONN_READ, conn->uid, count, n);
    FSTRACE(ASYNCTLS_CONN_READ_DUMP, conn->uid, buf, n);
    return n;
}

FSTRACE_DECL(ASYNCTLS_CONN_CLOSE, "UID=%64u");

void tls_close(tls_conn_t *conn)
{
    FSTRACE(ASYNCTLS_CONN_CLOSE, conn->uid);
    switch (conn->state) {
        case TLS_CONN_STATE_ZOMBIE:
            return;
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            break;
        default:
            bytestream_1_close_relaxed(conn->async, conn->plain_output_stream);
    }
    tls_free_underlying_resources(conn);
    bytestream_1_close(conn->encrypted_input_stream);
    if (conn->is_client)
        destroy_tls_ca_bundle(conn->client.ca_bundle);
    else if (!conn->server.credentials_shared)
        destroy_tls_credentials(conn->server.credentials);
    fsfree(conn->alpn_choice);
    if (conn->encrypted_output_closed)
        async_wound(conn->async, conn);
    tls_set_conn_state(conn, TLS_CONN_STATE_ZOMBIE);
}

void tls_close_asynctls_only(tls_conn_t *conn)
{
    switch (conn->state) {
        case TLS_CONN_STATE_ZOMBIE:
            return;
        case TLS_CONN_STATE_SHUT_DOWN_OUTGOING:
            break;
        default:
            bytestream_1_close_relaxed(conn->async, conn->plain_output_stream);
    }
    fsfree(conn->underlying_tech);
    if (conn->encrypted_output_closed)
        async_wound(conn->async, conn);
    tls_set_conn_state(conn, TLS_CONN_STATE_ZOMBIE);
}

FSTRACE_DECL(ASYNCTLS_CONN_REGISTER, "UID=%64u OBJ=%p ACT=%p");

void tls_register_callback(tls_conn_t *conn, action_1 action)
{
    FSTRACE(ASYNCTLS_CONN_REGISTER, conn->uid, action.obj, action.act);
    bytestream_1_register_callback(tls_get_plain_input_stream(conn), action);
}

FSTRACE_DECL(ASYNCTLS_CONN_UNREGISTER, "UID=%64u");

void tls_unregister_callback(tls_conn_t *conn)
{
    FSTRACE(ASYNCTLS_CONN_UNREGISTER, conn->uid);
    bytestream_1_unregister_callback(tls_get_plain_input_stream(conn));
}

FSTRACE_DECL(ASYNCTLS_CONN_SET_OUTPUT, "UID=%64u OUTPUT=%p")

void tls_set_plain_output_stream(tls_conn_t *conn, bytestream_1 output_stream)
{
    FSTRACE(ASYNCTLS_CONN_SET_OUTPUT, conn->uid, output_stream.obj);
    switch (conn->state) {
        case TLS_CONN_STATE_ZOMBIE:
            return;
        default:
            bytestream_1_close_relaxed(conn->async, conn->plain_output_stream);
    }
    conn->plain_output_stream = output_stream;
    action_1 plain_output_cb = { conn, (act_1) output_notification };
    bytestream_1_register_callback(output_stream, plain_output_cb);
    async_execute(conn->async, plain_output_cb);
}

const char* tls_get_server_name(tls_conn_t *conn){
    return conn->server_name;
}

FSTRACE_DECL(ASYNCTLS_CONN_REGISTER_HANDSHAKE, "UID=%64u OBJ=%p ACT=%p");

void tls_register_handshake_done_cb(tls_conn_t *conn, action_1 cb_action)
{
    FSTRACE(ASYNCTLS_CONN_REGISTER_HANDSHAKE,
            conn->uid, cb_action.obj, cb_action.act);
    conn->handshake_done_callback = cb_action;
}

FSTRACE_DECL(ASYNCTLS_CONN_UNREGISTER_HANDSHAKE, "UID=%64u");

void tls_unregister_handshake_done_cb(tls_conn_t *conn)
{
    FSTRACE(ASYNCTLS_CONN_UNREGISTER_HANDSHAKE, conn->uid);
    conn->handshake_done_callback = NULL_ACTION_1;
}
