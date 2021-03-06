#ifndef __TLS_UNDERLYING__
#define __TLS_UNDERLYING__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "tls_connection.h"

typedef enum {
    TLS_CONN_STATE_HANDSHAKING,
    TLS_CONN_STATE_OPEN,
    TLS_CONN_STATE_SHUT_DOWN_OUTGOING,
    TLS_CONN_STATE_DENIED,
    TLS_CONN_STATE_ERRORED,
    TLS_CONN_STATE_ZOMBIE
} tls_conn_state_t;

struct tls_conn {
    async_t *async;
    uint64_t uid;
    const char *server_name;
    bool is_client;
    union {
        struct {
            tls_ca_bundle_t *ca_bundle;
        } client;
        struct {
            bool credentials_shared;
            tls_credentials_t *credentials;
        } server;
    };
    char *alpn_choice;
    tls_conn_state_t state;
    bytestream_1 encrypted_input_stream;
    bytestream_1 plain_output_stream;
    action_1 plain_input_callback;
    action_1 encrypted_output_callback;
    action_1 handshake_done_callback;
    bool plain_input_closed;
    bool encrypted_output_closed;
    void *underlying_tech;
};

/*
 * Implemented in tls_connection.c
 */

/* Schedule data availability callbacks. */
void tls_notify_application(tls_conn_t *conn);
void tls_notify_transport(tls_conn_t *conn);
void tls_set_conn_state(tls_conn_t *conn, tls_conn_state_t state);
void tls_set_alpn_choice(tls_conn_t *conn, char *protocol);

/*
 * Implement in the underlying tech
 */

/* Called from the constructor to set conn->underlying_tech. */
void tls_initialize_underlying_client_tech(tls_conn_t *conn);
void tls_initialize_underlying_server_tech(tls_conn_t *conn);

void tls_adopt_tech(tls_conn_t *conn, void *_ssl);

/* Called from the destructor to release conn->underlying_tech. */
void tls_free_underlying_resources(tls_conn_t *conn);

/* This function is called only in TLS_CONN_STATE_HANDSHAKING, possibly
 * repeatedly.
 *
 * Return 0 and set the state to TLS_CONN_STATE_OPEN if the handshake
 * phase has completed successfully.
 *
 * Return -1 with EAGAIN without changing the state if more information
 * needs to be exchanged with the peer.
 *
 * Return -1 with EPROTO and set the state to TLS_CONN_STATE_ERRORED if
 * the TLS protocol was violated.
 *
 * Return -1 with EACCES and set the state to TLS_CONN_STATE_DENIED if
 * the handshake resulted in access denial. */
int tls_perform_handshake(tls_conn_t *conn);

/* Set the connection state as a side effect to reading. */
ssize_t tls_read_encrypted_output(tls_conn_t *conn, void *buf, size_t count);
ssize_t tls_read_plain_input(tls_conn_t *conn, void *buf, size_t count);

#ifdef __cplusplus
}
#endif

#endif
