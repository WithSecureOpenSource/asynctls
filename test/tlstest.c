#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <async/async.h>
#include <async/farewellstream.h>
#include <async/queuestream.h>
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
    tcp_conn_t *tcp_conn;
    tls_conn_t *tls_conn;
    queuestream_t *output_stream;
    bool zombie, all_received;
} globals_t;

static void perrmsg(const char *name)
{
    fprintf(stderr, "tlstest: %s\n", name);
}

static int resolve_ipv4(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in)) {
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in *) *address)->sin_port = htons(port);
    return 1;
}

static int resolve_ipv6(struct addrinfo *res, int port,
                        struct sockaddr **address, socklen_t *addrlen)
{
    if (res->ai_addrlen < sizeof(struct sockaddr_in6)) {
        perrmsg("resolved address too short");
        return 0;
    }
    *addrlen = res->ai_addrlen;
    *address = malloc(*addrlen);
    memcpy(*address, res->ai_addr, *addrlen);
    ((struct sockaddr_in6 *) *address)->sin6_port = htons(port);
    return 1;
}

static int resolve_address(const char *host, int port,
                           struct sockaddr **address, socklen_t *addrlen)
{
    struct addrinfo *res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    int status = getaddrinfo(host, NULL, &hints, &res);
    if (status) {
        perrmsg(gai_strerror(status));
        return 0;
    }
    int ret = 0;
    switch (res->ai_family) {
        case AF_INET:
            ret = resolve_ipv4(res, port, address, addrlen);
            break;
        case AF_INET6:
            ret = resolve_ipv6(res, port, address, addrlen);
            break;
        default:
            perrmsg("unsupported hostname resolution");
            break;
    }
    freeaddrinfo(res);
    return ret;
}

static void finish(globals_t *g)
{
    if (g->zombie) {
        return;
    }
    tls_close(g->tls_conn);
    tcp_close(g->tcp_conn);
    action_1 quit = { g->async, (act_1) async_quit_loop };
    async_execute(g->async, quit);
    g->zombie = true;
}

static void done_maybe(globals_t *g)
{
    if (!g->all_received)
        return;
    perrmsg("Done!");
    async_execute(g->async, (action_1) { g, (act_1) finish });
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
            perror("tlstest");
            async_execute(g->async, (action_1) { g, (act_1) finish });
            return;
        }
        if (count == 0) {
            queuestream_terminate(g->output_stream);
            perrmsg("All received");
            g->all_received = true;
            done_maybe(g);
            return;
        }
        write(1, buf, count);
    }
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

static void usage()
{
    fprintf(stderr,
            "Usage: tlstest [ --file pem-file | --dir pem-dir ] "
            "host port certificate_host\n");
}

int main(int argc, const char *const *argv)
{
    if (argc < 3) {
        usage();
        return EXIT_FAILURE;
    }

    // static const char *trace_include = ".";
    static const char *trace_include = NULL;
    fstrace_t *trace = set_up_tracing(trace_include, NULL);
    if (!trace) {
        return EXIT_FAILURE;
    }

    globals_t g;
    const char *pem_file_pathname = NULL;
    const char *pem_dir_pathname = NULL;
    int i = 1;
    if (!strcmp(argv[i], "--file")) {
        i++;
        pem_file_pathname = argv[i++];
    } else if (!strcmp(argv[i], "--dir")) {
        i++;
        pem_dir_pathname = argv[i++];
    }
    if (i + 3 > argc) {
        usage();
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    const char *hostname = argv[i++];
    int port = atoi(argv[i++]);
    const char *server_hostname = argv[i++];
    struct sockaddr *address;
    socklen_t addrlen;
    if (!resolve_address(hostname, port, &address, &addrlen)) {
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    g.async = make_async();
    g.zombie = g.all_received = false;
    g.tcp_conn = tcp_connect(g.async, NULL, address, addrlen);
    free(address);
    if (!g.tcp_conn) {
        perror("tlstest");
        destroy_async(g.async);
        fstrace_close(trace);
        return EXIT_FAILURE;
    }
    g.tls_conn =
        open_tls_client(g.async, tcp_get_input_stream(g.tcp_conn),
                        pem_file_pathname, pem_dir_pathname, server_hostname);
    tcp_set_output_stream(g.tcp_conn,
                          tls_get_encrypted_output_stream(g.tls_conn));
    action_1 probe_plain_input_cb = { &g, (act_1) probe_plain_input };
    tls_register_callback(g.tls_conn, probe_plain_input_cb);
    async_execute(g.async, probe_plain_input_cb);
    g.output_stream = make_queuestream(g.async);
    bytestream_1 stream = queuestream_as_bytestream_1(g.output_stream);
    tls_set_plain_output_stream(g.tls_conn, stream);
    char content[1000];
    size_t len = snprintf(content, sizeof(content),
                          "GET / HTTP/1.0\r\n"
                          "Host: %s:%d\r\n"
                          "\r\n",
                          server_hostname, port);
    content[len] = '\0';
    bytestream_1 request =
        stringstream_as_bytestream_1(open_stringstream(g.async, content));
    queuestream_enqueue(g.output_stream, request);
    while (async_loop(g.async) < 0)
        if (errno != EINTR) {
            perror("tlstest");
            destroy_async(g.async);
            fstrace_close(trace);
            return EXIT_FAILURE;
        }
    destroy_async(g.async);
    fstrace_close(trace);
    if (g.all_received) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
