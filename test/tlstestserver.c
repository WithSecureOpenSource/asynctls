#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <async/async.h>
#include <async/farewellstream.h>
#include <async/stringstream.h>
#include <async/tcp_connection.h>
#include <async/tls_connection.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

#ifndef ENODATA
#define ENODATA ECONNABORTED
#endif

typedef struct {
    async_t *async;
    tcp_server_t *server;
    const char *cert_chain_pathname;
    const char *priv_key_pathname;
    tcp_conn_t *tcp_conn;
    tls_conn_t *tls_conn;
    bool zombie, all_sent, all_received;
} globals_t;

static void perrmsg(const char *name)
{
    fprintf(stderr, "tlstestserver: %s\n", name);
}

static void done_maybe(globals_t *g)
{
    if (!g->all_sent || !g->all_received)
        return;
    perrmsg("Done!");
    tls_close(g->tls_conn);
    tcp_close(g->tcp_conn);
    action_1 quit = { g->async, (act_1) async_quit_loop };
    async_execute(g->async, quit);
    g->zombie = true;
}

static void probe_plain_input(globals_t *g)
{
    if (g->all_received)
        return;
    for (;;) {
        char buf[2000];
        ssize_t count = tls_read(g->tls_conn, buf, sizeof buf);
        if (count < 0) {
            if (errno == EAGAIN)
                return;
            if (errno == ENODATA) {
                perrmsg("Ragged EOF -- all received");
                g->all_received = true;
                done_maybe(g);
                return;
            }
            perror("tlstestserver");
            async_quit_loop(g->async);
            return;
        }
        if (count == 0) {
            perrmsg("All received");
            g->all_received = true;
            done_maybe(g);
            return;
        }
        write(1, buf, count);
    }
}

static void all_sent(globals_t *g)
{
    perrmsg("All sent");
    g->all_sent = true;
    done_maybe(g);
}

static void probe_server(globals_t *g)
{
    if (g->zombie || !g->server)
        return;
    g->tcp_conn = tcp_accept(g->server, NULL, NULL);
    if (!g->tcp_conn) {
        assert(errno == EAGAIN);
        return;
    }
    tcp_close_server(g->server);
    g->server = NULL;
    g->tls_conn = open_tls_server(g->async, tcp_get_input_stream(g->tcp_conn),
                                  g->cert_chain_pathname, g->priv_key_pathname);
    tcp_set_output_stream(g->tcp_conn,
                          tls_get_encrypted_output_stream(g->tls_conn));
    action_1 probe_plain_input_cb = { g, (act_1) probe_plain_input };
    tls_register_callback(g->tls_conn, probe_plain_input_cb);
    async_execute(g->async, probe_plain_input_cb);
    bytestream_1 response = stringstream_as_bytestream_1(
        open_stringstream(g->async, "hello there\n"));
    action_1 farewell_cb = { g, (act_1) all_sent };
    farewellstream_t *guard =
        open_relaxed_farewellstream(g->async, response, farewell_cb);
    tls_set_plain_output_stream(g->tls_conn,
                                farewellstream_as_bytestream_1(guard));
}

static fstrace_t *set_up_tracing(const char *trace_include,
                                 const char *trace_exclude)
{
    fstrace_t *trace = fstrace_direct(stderr);
    fstrace_declare_globals(trace);
    if (!fstrace_select_regex(trace, trace_include, trace_exclude)) {
        fstrace_close(trace);
        return NULL;
    }
    return trace;
}

static bool write_pidfile(const char *pidfile)
{
    bool error = false;
    FILE *fp = fopen(pidfile, "w");
    if (!fp)
        return false;
    error |= fprintf(fp, "%ld", (long) getpid()) < 0;
    error |= fclose(fp) == EOF;
    return !error;
}

static void usage()
{
    fprintf(stderr,
            "Usage: tlstestserver cert-chain-file priv-key-file pidfile\n");
}

int main(int argc, const char *const *argv)
{
    if (argc != 4 || argv[1][0] == '-') {
        usage();
        return EXIT_FAILURE;
    }

    // static const char *trace_include = ".";
    static const char *trace_include = NULL;
    fstrace_t *trace = set_up_tracing(trace_include, NULL);
    if (!trace) {
        return EXIT_FAILURE;
    }

    globals_t g = {
        .cert_chain_pathname = argv[1],
        .priv_key_pathname = argv[2],
    };
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(12345),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };

    g.async = make_async();
    g.zombie = g.all_sent = g.all_received = false;
    g.server =
        tcp_listen(g.async, (struct sockaddr *) &address, sizeof address);
    if (!g.server || !write_pidfile(argv[3])) {
        perror("tlstestserver");
        destroy_async(g.async);
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    action_1 server_cb = { &g, (act_1) probe_server };
    tcp_register_server_callback(g.server, server_cb);
    async_execute(g.async, server_cb);
    while (async_loop(g.async) < 0) {
        if (errno != EINTR) {
            perror("tlstest");
            destroy_async(g.async);
            fstrace_close(trace);
            return EXIT_FAILURE;
        }
    }
    destroy_async(g.async);
    fstrace_close(trace);
    if (g.all_sent && g.all_received) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
