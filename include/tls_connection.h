#ifndef __TLS_CONNECTION__
#define __TLS_CONNECTION__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A TLS connection object provides encryption/decryption between an
 * application (eg, HTTP) and a transport (eg, TCP):
 *
 *
 *                plain text                  encrypted
 *              <------------>              <------------>
 *
 * +-----------+              +------------+              +------------+
 * | app       |              | tls_conn_t |              | transport  |
 * |  +--------+       read() |   +--------+       read() |            |
 * |  |        |<-------------+   |        |<-------------+            |
 * |  |        |              |   |        |              |            |
 * |  | plain  |      close() |   | encr'd |      close() |            |
 * |  | output |<-------------+   | output |<-------------+            |
 * |  | stream |              |   | stream |              |            |
 * |  |        | callback     |   |        | callback     |            |
 * |  |        +------------->|   |        +------------->|            |
 * |  +--------+              |   +--------+              |            |
 * |           | read()       +--------+   | read()       |---------+  |
 * |           +------------->|        |   +------------->|         |  |
 * |           |              |        |   |              |         |  |
 * |           | close()      | plain  |   | close()      | encr'd  |  |
 * |           +------------->| input  |   +------------->| input   |  |
 * |           |              | stream |   |              | stream  |  |
 * |           |     callback |        |   |     callback |         |  |
 * |           |<-------------+        |   |<-------------+         |  |
 * +-----------+              +--------+---+              +---------+--+
 *
 * Use these functions to make the four stream interconnects:
 *  - open_tls_client(encrypted_input_stream)
 *  - tls_get_encrypted_output_stream()
 *  - tls_set_plain_output_stream()
 *  - tls_get_plain_input_stream()
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <async/async.h>
#include <async/bytestream_1.h>

typedef struct tls_conn tls_conn_t;
typedef struct tls_ca_bundle tls_ca_bundle_t;
typedef struct tls_credentials tls_credentials_t;

/* The client constructor. Makes one of the four necessary stream
 * interconnects.
 *
 * The string arguments 'pem_file_pathname', 'pem_dir_pathname' and
 * 'peer_hostname' are expected to stay valid for the lifetime of the
 * TLS connection.
 * If 'pem_file_pathname' and 'pem_dir_pathname' are both NULL, the default
 * pem file and pem directory of the running machine is used. */
tls_conn_t *open_tls_client(async_t *async,
                            bytestream_1 encrypted_input_stream,
                            const char *pem_file_pathname,
                            const char *pem_dir_pathname,
                            const char *server_hostname);

/* While each call to open_tls_client() constructs a separate CA bundle,
 * open_tls_client_2() allows for sharing one CA bundle among several
 * connections, which should be better for performance. The bundle
 * should exist for as long as the TLS connection exists. */
tls_conn_t *open_tls_client_2(async_t *async,
                              bytestream_1 encrypted_input_stream,
                              tls_ca_bundle_t *ca_bundle,
                              const char *server_hostname);

/* Make asynctls take control over tls context, created elsewhere.
 * WARNING: This function is very implementation specific, so you must ensure
 * that underlying implementation of asynctls matches the one you are using. */
tls_conn_t *adopt_tls_client(async_t *async,
                             bytestream_1 encrypted_input_stream,
                             tls_ca_bundle_t *ca_bundle,
                             void *underlying_connection);

/* The system CA bundle is available through this variable. */
extern tls_ca_bundle_t *TLS_SYSTEM_CA_BUNDLE;

/* If both pem_file_pathname and pem_dir_pathname are NULL, use the
 * system's default certificate store. (See also TLS_SYSTEM_CA_BUNDLE
 * above.) */
tls_ca_bundle_t *make_tls_ca_bundle(const char *pem_file_pathname,
                                    const char *pem_dir_pathname);

/* Create a pseudo-ca-bundle, which accepts the connection without
 * certificate validation. */
tls_ca_bundle_t *make_unverified_tls_ca_bundle(void);

/* Create a pseudo-ca-bundle, which verifies the connection using the
 * given callback function. */
tls_ca_bundle_t *make_synthetic_tls_ca_bundle(bool (*verify)(void *user_data),
                                              void *user_data);

/* Create a pseudo-ca-bundle, which verifies the connection using one
 * of the given leaf certificates. If pem_file_pathname is non-NULL,
 * pem_dir_pathname is ignored. If both pem_file_pathname and
 * pem_dir_pathname are NULL, the returned bundle fails all
 * connections. */
tls_ca_bundle_t *make_pinned_tls_ca_bundle(const char *pem_file_pathname,
                                           const char *pem_dir_pathname);

void destroy_tls_ca_bundle(tls_ca_bundle_t *ca_bundle);

tls_conn_t *open_tls_server(async_t *async,
                            bytestream_1 encrypted_input_stream,
                            const char *pem_cert_chain_pathname,
                            const char *pem_priv_key_pathname);
tls_conn_t *open_tls_server_2(async_t *async,
                              bytestream_1 encrypted_input_stream,
                              tls_credentials_t *credentials);

/* Make asynctls take control over tls context, created elsewhere.
 * WARNING: This function is very implementation specific, so you must ensure
 * that underlying implementation of asynctls matches the one you are using. */
tls_conn_t *adopt_tls_server(async_t *async,
                             bytestream_1 encrypted_input_stream,
                             tls_credentials_t *credentials,
                             void *underlying_connection);

tls_credentials_t *make_tls_credentials(const char *pem_cert_chain_pathname,
                                        const char *pem_priv_key_pathname);

tls_credentials_t *make_tls_credentials_2(const char *pem_cert_chain_pathname,
                                          const char *pem_priv_key_pathname,
                                          const char *password);

void destroy_tls_credentials(tls_credentials_t *credentials);

bytestream_1 tls_get_encrypted_output_stream(tls_conn_t *conn);
void tls_set_plain_output_stream(tls_conn_t *conn, bytestream_1 output_stream);
bytestream_1 tls_get_plain_input_stream(tls_conn_t *conn);

/* Register a callback issued upon ending of the handshake procedure.
 *
 * Be sure to call this function before reading from conn's streams.
 * Otherwise, the handshake may complete before the callback is
 * registered.
 *
 * Note that the callback might be delivered after the first cleartext
 * bytes have already been read out of the plain input stream. That's
 * why tls_read(conn, NULL 0) is a more recommended way to discover
 * when the handshake is complete. */
void tls_register_handshake_done_cb(tls_conn_t *conn, action_1 cb_action);

/* Unregister the handshake completed callback. Note that this
 * function cannot cancel an already issued callback. */
void tls_unregister_handshake_done_cb(tls_conn_t *conn);

/*
 * Return the currently configured server name. On the client side,
 * the default name is the one provided via at the time of creation of
 * the tls object via the open_tls_client call. This will be
 * eventually overwritten by any SNI specified by the client (on the
 * server side).
 *
 * To be used only after handshake completion. Otherwise results might
 * be undefined. (See tls_register_handshake_done_cb above).
*/
const char *tls_get_server_name(tls_conn_t *conn);

/* This function is used by the client to inform the server (through
 * the ALPN extension) about the acceptability of one or more
 * protocols. Call the function separately for each protocol. If the
 * function is not called, no ALPN exchange will take place.
 *
 * Terminate the protocol list with (const char *) NULL.
 *
 * Be sure to call this function before reading from conn's streams.
 */
void tls_allow_protocols(tls_conn_t *conn, const char *protocol, ...);

/* After the successful completion of a handshake, the client can use
 * this function to get the protocol token chosen by the server
 * (through the ALPN extension). NULL is returned if no choice was made.
 *
 * The returned string is NUL-terminated and stays available for the
 * lifetime of the connection. */
const char *tls_get_chosen_protocol(tls_conn_t *conn);

/* Close the TLS connection and release the associated resources:
 *
 *  - The plain and encrypted input streams are closed immediately.
 *
 *  - Subsequent reads from the encrypted output stream will yield an
 *    error (EBADF). The transport must close the stream eventually.
 *
 *  - The plain output stream will be closed eventually. */
void tls_close(tls_conn_t *conn);

/* Close the adopted TLS connection, just releasing asynctls resources.
 * WARNING: This function is very implementation specific, so you must know what
 * you are doing if you call this function. */
void tls_close_asynctls_only(tls_conn_t *conn);

/* Equivalent to:
 *
 *   bytestream_1_read(tls_get_plain_input_stream(conn), buf, count)
 *
 * Note that reading 0 bytes is a way to probe the initial handshake.
 * If count == 0, a zero return indicates a completed handshake.
 */
ssize_t tls_read(tls_conn_t *conn, void *buf, size_t count);

/* Equivalent to:
 *
 *   bytestream_1_register_callback(tls_get_plain_input_stream(conn), action)
 */
void tls_register_callback(tls_conn_t *conn, action_1 action);

/* Equivalent to:
 *
 *   bytestream_1_unregister_callback(tls_get_plain_input_stream(conn))
 */
void tls_unregister_callback(tls_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
