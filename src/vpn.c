#include <yaml.h>
#include "vpn.h"
#include "charm.h"
#include "os.h"

static const int POLLFD_TUN = 0, POLLFD_LISTENER = 1, POLLFD_CLIENT = 2, POLLFD_COUNT = 3;

typedef struct __attribute__((aligned(16))) Buf_ {
#if TAG_LEN < 16 - 2
    unsigned char _pad[16 - TAG_LEN - 2];
#endif
    unsigned char len[2];
    unsigned char tag[TAG_LEN];
    unsigned char data[MAX_PACKET_LEN];
    size_t        pos;
} Buf;

typedef struct Context_ {
    const char   *wanted_if_name;
    const char   *local_tun_ip;
    const char   *remote_tun_ip;
    const char   *local_tun_ip6;
    const char   *remote_tun_ip6;
    const char   *server_ip_or_name;
    const char   *server_port;
    const char   *ext_if_name;
    const char   *wanted_ext_gw_ip;
	// --- 新增：用于存储从 YAML 读取的配置内容的缓冲区 ---
    char          key_file_buf[256];
    char          server_ip_or_name_buf[128];
    char          server_port_buf[16];
    char          wanted_if_name_buf[IFNAMSIZ];
    char          local_tun_ip_buf[64];
    char          remote_tun_ip_buf[64];
    char          local_tun_ip6_buf[64];
    char          remote_tun_ip6_buf[64];
    char          wanted_ext_gw_ip_buf[64];
	// 新增 Brutal 字段
    int           brutal_enabled;
    uint64_t      brutal_rate;
    char          client_ip[NI_MAXHOST];
    char          ext_gw_ip[64];
    char          server_ip[64];
    char          if_name[IFNAMSIZ];
    int           is_server;
    int           tun_fd;
    int           client_fd;
    int           listen_fd;
    int           congestion;
    int           firewall_rules_set;
    Buf           client_buf;
    struct pollfd fds[3];
    uint32_t      uc_kx_st[12];
    uint32_t      uc_st[2][12];
} Context;

volatile sig_atomic_t exit_signal_received;

static void signal_handler(int sig)
{
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}

static int firewall_rules(Context *context, int set, int silent)
{
    const char        *substs[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                       { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                       { "$LOCAL_TUN_IP", context->local_tun_ip },
                                       { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                       { "$EXT_IP", context->server_ip },
                                       { "$EXT_PORT", context->server_port },
                                       { "$EXT_IF_NAME", context->ext_if_name },
                                       { "$EXT_GW_IP", context->ext_gw_ip },
                                       { "$IF_NAME", context->if_name },
                                       { NULL, NULL } };
    const char *const *cmds;
    size_t             i;

    if (context->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(context->is_server).set
                     : firewall_rules_cmds(context->is_server).unset)) == NULL) {
        fprintf(stderr,
                "Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i], silent) != 0) {
            fprintf(stderr, "Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    context->firewall_rules_set = set;
    return 0;
}

static int tcp_client(Context *context, const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai;
    int             client_fd;
    int             err;

    printf("Connecting to %s:%s...\n", address, port);
    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the client socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }

    if ((client_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        tcp_opts(client_fd, context->brutal_enabled, context->brutal_rate) != 0) {
        freeaddrinfo(res);
        if (client_fd != -1) close(client_fd);
        return -1;
    }

    // 1. 发起连接前，先将 Socket 设置为非阻塞模式
    fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK);

    // 2. 发起非阻塞 Connect
    if (connect(client_fd, (const struct sockaddr *) res->ai_addr, res->ai_addrlen) != 0) {
        if (errno != EINPROGRESS) {
            err = errno;
            close(client_fd);
            freeaddrinfo(res);
            errno = err;
            return -1;
        }

        // 3. 使用 poll 等待连接结果，严格设置 3000ms (3秒) 超时
        struct pollfd pfd = { .fd = client_fd, .events = POLLOUT };
        if (poll(&pfd, 1, 3000) <= 0) {
            close(client_fd);
            freeaddrinfo(res);
            errno = ETIMEDOUT;
            return -1;
        }

        // 4. 检查是否真正握手成功
        int optval = 0;
        socklen_t optlen = sizeof(optval);
        if (getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0 || optval != 0) {
            close(client_fd);
            freeaddrinfo(res);
            errno = optval ? optval : ECONNREFUSED;
            return -1;
        }
    }

    freeaddrinfo(res);
    return client_fd;
}

static int tcp_listener(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai, err;
    int             listen_fd;
    int             backlog = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
#if defined(__OpenBSD__) || defined(__DragonFly__)
    if (address == NULL) {
        hints.ai_family = AF_INET;
    }
#endif
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the listening socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((listen_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *) (int[]) { 1 }, sizeof(int)) != 0) {
        err = errno;
        (void) close(listen_fd);
        freeaddrinfo(res);
        errno = err;
        return -1;
    }
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    (void) setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) (int[]) { 0 }, sizeof(int));
#endif
#ifdef TCP_DEFER_ACCEPT
    (void) setsockopt(listen_fd, SOL_TCP, TCP_DEFER_ACCEPT,
                      (char *) (int[]) { ACCEPT_TIMEOUT / 1000 }, sizeof(int));
#endif
    printf("Listening to %s:%s\n", address == NULL ? "*" : address, port);
    if (bind(listen_fd, (struct sockaddr *) res->ai_addr, (socklen_t) res->ai_addrlen) != 0 ||
        listen(listen_fd, backlog) != 0) {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return listen_fd;
}

static void client_disconnect(Context *context)
{
    if (context->client_fd == -1) {
        return;
    }
    (void) close(context->client_fd);
    context->client_fd          = -1;
    context->fds[POLLFD_CLIENT] = (struct pollfd) { .fd = -1, .events = 0 };
    memset(context->uc_st, 0, sizeof context->uc_st);
}

static int server_key_exchange(Context *context, const int client_fd)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t ts, now;

    memcpy(st, context->uc_kx_st, sizeof st);
    errno = EACCES;
    if (safe_read(client_fd, pkt1, sizeof pkt1, ACCEPT_TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    uc_hash(st, h, pkt1, 32 + 8);
    if (memcmp(h, pkt1 + 32 + 8, 32) != 0) {
        return -1;
    }
    memcpy(&ts, pkt1 + 32, 8);
    ts  = endian_swap64(ts);
    now = time(NULL);
    if ((ts > now && ts - now > TS_TOLERANCE) || (now > ts && now - ts > TS_TOLERANCE)) {
        fprintf(stderr,
                "Clock difference is too large: %" PRIu64 " (client) vs %" PRIu64 " (server)\n", ts,
                now);
        return -1;
    }
    uc_randombytes_buf(pkt2, 32);
    uc_hash(st, pkt2 + 32, pkt2, 32);
    if (safe_write_partial(client_fd, pkt2, sizeof pkt2) != sizeof pkt2) {
        return -1;
    }
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int tcp_accept(Context *context, int listen_fd)
{
    char                    client_ip[NI_MAXHOST] = { 0 };
    struct sockaddr_storage client_ss;
    socklen_t               client_ss_len = sizeof client_ss;
    int                     client_fd;
    int                     err;

    if ((client_fd = accept(listen_fd, (struct sockaddr *) &client_ss, &client_ss_len)) < 0) {
        return -1;
    }
	// 对 accept 返回的新 client_fd 设置 socket 选项
    if (tcp_opts(client_fd, context->brutal_enabled, context->brutal_rate) != 0) { 
        return -1;
    }
    if (client_ss_len <= (socklen_t) 0U) {
        (void) close(client_fd);
        errno = EINTR;
        return -1;
    }
    if (tcp_opts(client_fd, context->brutal_enabled, context->brutal_rate) != 0) {
        err = errno;
        (void) close(client_fd);
        errno = err;
        return -1;
    }
    getnameinfo((const struct sockaddr *) (const void *) &client_ss, client_ss_len, client_ip,
                sizeof client_ip, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
    printf("Connection attempt from [%s]\n", client_ip);
    context->congestion = 0;
    fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK);
    if (context->client_fd != -1 &&
        memcmp(context->client_ip, client_ip, sizeof context->client_ip) != 0) {
        fprintf(stderr, "Closing: a session from [%s] is already active\n", context->client_ip);
        (void) close(client_fd);
        errno = EBUSY;
        return -1;
    }
    if (server_key_exchange(context, client_fd) != 0) {
        fprintf(stderr, "Authentication failed\n");
        (void) close(client_fd);
        errno = EACCES;
        return -1;
    }
    memcpy(context->client_ip, client_ip, sizeof context->client_ip);
    return client_fd;
}

static int client_key_exchange(Context *context)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t now;

    memcpy(st, context->uc_kx_st, sizeof st);
    uc_randombytes_buf(pkt1, 32);
    now = endian_swap64(time(NULL));
    memcpy(pkt1 + 32, &now, 8);
    uc_hash(st, pkt1 + 32 + 8, pkt1, 32 + 8);
    if (safe_write(context->client_fd, pkt1, sizeof pkt1, TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    errno = EACCES;
    if (safe_read(context->client_fd, pkt2, sizeof pkt2, TIMEOUT) != sizeof pkt2) {
        return -1;
    }
    uc_hash(st, h, pkt2, 32);
    if (memcmp(h, pkt2 + 32, 32) != 0) {
        return -1;
    }
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int client_connect(Context *context)
{
    const char *ext_gw_ip = NULL;

    context->client_buf.pos = 0;
    memset(context->client_buf.data, 0, sizeof context->client_buf.data);
#ifndef NO_DEFAULT_ROUTES
    if (context->wanted_ext_gw_ip == NULL && (ext_gw_ip = get_default_gw_ip()) != NULL &&
        strcmp(ext_gw_ip, context->ext_gw_ip) != 0) {
        printf("Gateway changed from [%s] to [%s]\n", context->ext_gw_ip, ext_gw_ip);
        firewall_rules(context, 0, 0);
        snprintf(context->ext_gw_ip, sizeof context->ext_gw_ip, "%s", ext_gw_ip);
        firewall_rules(context, 1, 0);
    }
#endif
    memset(context->uc_st, 0, sizeof context->uc_st);
    context->uc_st[context->is_server][0] ^= 1;
    context->client_fd = tcp_client(context, context->server_ip, context->server_port);
    if (context->client_fd == -1) {
        perror("Client connection failed");
        return -1;
    }
    fcntl(context->client_fd, F_SETFL, fcntl(context->client_fd, F_GETFL, 0) | O_NONBLOCK);
    context->congestion = 0;
    if (client_key_exchange(context) != 0) {
        fprintf(stderr, "Authentication failed\n");
        client_disconnect(context);
        sleep(1);
        return -1;
    }
    firewall_rules(context, 1, 0);
    context->fds[POLLFD_CLIENT] =
        (struct pollfd) { .fd = context->client_fd, .events = POLLIN, .revents = 0 };
    puts("Connected");

    return 0;
}

static int client_reconnect(Context *context)
{
    unsigned int i;

    client_disconnect(context);
    if (context->is_server) {
        return 0;
    }
    for (i = 0; exit_signal_received == 0 && i < RECONNECT_ATTEMPTS; i++) {
        puts("Trying to reconnect");
        sleep(i > 3 ? 3 : i);
        if (client_connect(context) == 0) {
            return 0;
        }
    }
    return -1;
}

static int event_loop(Context *context)
{
    struct pollfd *const fds = context->fds;
    Buf                  tun_buf;
    Buf                 *client_buf = &context->client_buf;
    ssize_t              len;
    int                  found_fds;
    int                  new_client_fd;

    if (exit_signal_received != 0) {
        return -2;
    }
    if ((found_fds = poll(fds, POLLFD_COUNT, 1500)) == -1) {
        return errno == EINTR ? 0 : -1;
    }
    if (fds[POLLFD_LISTENER].revents & POLLIN) {
        new_client_fd = tcp_accept(context, context->listen_fd);
        if (new_client_fd == -1) {
            perror("Accepting a new client failed");
            return 0;
        }
        if (context->client_fd != -1) {
            (void) close(context->client_fd);
            sleep(1);
        }
        context->client_fd = new_client_fd;
        client_buf->pos    = 0;
        memset(client_buf->data, 0, sizeof client_buf->data);
        puts("Session established");
        fds[POLLFD_CLIENT] = (struct pollfd) { .fd = context->client_fd, .events = POLLIN };
    }
    if ((fds[POLLFD_TUN].revents & POLLERR) || (fds[POLLFD_TUN].revents & POLLHUP)) {
        puts("HUP (tun)");
        return -1;
    }
    if (fds[POLLFD_TUN].revents & POLLIN) {
        len = tun_read(context->tun_fd, tun_buf.data, sizeof tun_buf.data);
        if (len <= 0) {
            perror("tun_read");
            return -1;
        }
#ifdef BUFFERBLOAT_CONTROL
        if (context->congestion) {
            context->congestion = 0;
            return 0;
        }
#endif
        if (context->client_fd != -1) {
            unsigned char tag_full[16];
            ssize_t       writenb;
            uint16_t      binlen = endian_swap16((uint16_t) len);

            memcpy(tun_buf.len, &binlen, 2);
            uc_encrypt(context->uc_st[0], tun_buf.data, len, tag_full);
            memcpy(tun_buf.tag, tag_full, TAG_LEN);
            writenb = safe_write_partial(context->client_fd, tun_buf.len, 2U + TAG_LEN + len);
            if (writenb < (ssize_t) 0) {
                context->congestion = 1;
                writenb             = (ssize_t) 0;
            }
            if (writenb != (ssize_t) (2U + TAG_LEN + len)) {
                writenb = safe_write(context->client_fd, tun_buf.len + writenb,
                                     2U + TAG_LEN + len - writenb, TIMEOUT);
            }
            if (writenb < (ssize_t) 0) {
                perror("Unable to write data to the TCP socket");
                return client_reconnect(context);
            }
        }
    }
    if ((fds[POLLFD_CLIENT].revents & POLLERR) || (fds[POLLFD_CLIENT].revents & POLLHUP)) {
        puts("Client disconnected");
        return client_reconnect(context);
    }
    if (fds[POLLFD_CLIENT].revents & POLLIN) {
        uint16_t binlen;
        size_t   len_with_header;
        ssize_t  readnb;

        if ((readnb = safe_read_partial(context->client_fd, client_buf->len + client_buf->pos,
                                        2 + TAG_LEN + MAX_PACKET_LEN - client_buf->pos)) <= 0) {
            puts("Client disconnected");
            return client_reconnect(context);
        }
        client_buf->pos += readnb;
        while (client_buf->pos >= 2 + TAG_LEN) {
            memcpy(&binlen, client_buf->len, 2);
            len = (ssize_t) endian_swap16(binlen);
            if (client_buf->pos < (len_with_header = 2 + TAG_LEN + (size_t) len)) {
                break;
            }
            if ((size_t) len > sizeof client_buf->data ||
                uc_decrypt(context->uc_st[1], client_buf->data, (size_t) len, client_buf->tag,
                           TAG_LEN) != 0) {
                fprintf(stderr, "Corrupted stream\n");
                sleep(1);
                return client_reconnect(context);
            }
            if (tun_write(context->tun_fd, client_buf->data, (size_t) len) != len) {
                perror("tun_write");
            }
            if (2 + TAG_LEN + MAX_PACKET_LEN != len_with_header) {
                unsigned char *rbuf      = client_buf->len;
                size_t         remaining = client_buf->pos - len_with_header;
                memmove(rbuf, rbuf + len_with_header, remaining);
            }
            client_buf->pos -= len_with_header;
        }
    }
    return 0;
}

static int doit(Context *context)
{
    context->client_fd = context->listen_fd = -1;
    memset(context->fds, 0, sizeof *context->fds);
    context->fds[POLLFD_TUN] =
        (struct pollfd) { .fd = context->tun_fd, .events = POLLIN, .revents = 0 };
    if (context->is_server) {
        if ((context->listen_fd = tcp_listener(context->server_ip_or_name, context->server_port)) ==
            -1) {
            perror("Unable to set up a TCP server");
            return -1;
        }
        context->fds[POLLFD_LISTENER] = (struct pollfd) {
            .fd     = context->listen_fd,
            .events = POLLIN,
        };
    }
    if (!context->is_server && client_reconnect(context) != 0) {
        fprintf(stderr, "Unable to connect to server: [%s]\n", strerror(errno));
        return -1;
    }
    while (event_loop(context) == 0)
        ;
    return 0;
}

static int load_key_file(Context *context, const char *file)
{
    unsigned char key[32];
    int           fd;

    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (safe_read(fd, key, sizeof key, -1) != sizeof key) {
        (void) close(fd);
        return -1;
    }
    uc_state_init(context->uc_kx_st, key, (const unsigned char *) "VPN Key Exchange");
    uc_memzero(key, sizeof key);

    return close(fd);
}

__attribute__((noreturn)) static void usage(void)
{
    puts("DSVPN " VERSION_STRING
         " usage:\n"
         "\n"
         "sudo ./dsvpn <config.yaml>\n\n"
         "Please provide a valid YAML configuration file.\n");
    exit(254);
}

static void get_tun6_addresses(Context *context)
{
    // 如果在 YAML 中已经配置了 IPv6，则直接使用配置的值
    if (context->local_tun_ip6_buf[0] != '\0' && context->remote_tun_ip6_buf[0] != '\0') {
        context->local_tun_ip6 = context->local_tun_ip6_buf;
        context->remote_tun_ip6 = context->remote_tun_ip6_buf;
        return;
    }

    // 否则，回退到原版的自动生成逻辑 (NAT64 前缀)
    static char local_tun_ip6[40], remote_tun_ip6[40];
    snprintf(local_tun_ip6, sizeof local_tun_ip6, "64:ff9b::%s", context->local_tun_ip);
    snprintf(remote_tun_ip6, sizeof remote_tun_ip6, "64:ff9b::%s", context->remote_tun_ip);
    
    context->local_tun_ip6  = local_tun_ip6;
    context->remote_tun_ip6 = remote_tun_ip6;
}

static int resolve_ip(char *ip, size_t sizeof_ip, const char *ip_or_name)
{
    struct addrinfo hints, *res = NULL;
    int             eai;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(ip_or_name, NULL, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6) ||
        (eai = getnameinfo(res->ai_addr, res->ai_addrlen, ip, (socklen_t) sizeof_ip, NULL, 0,
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        fprintf(stderr, "Unable to resolve [%s]: [%s]\n", ip_or_name, gai_strerror(eai));
        if (res != NULL) {
            freeaddrinfo(res);
        }
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

static int load_yaml_config(const char *filename, Context *ctx) {
    FILE *fh = fopen(filename, "r");
    if (!fh) {
        fprintf(stderr, "Cannot open config file: %s\n", filename);
        return -1;
    }

    yaml_parser_t parser;
    yaml_event_t  event;
    if (!yaml_parser_initialize(&parser)) {
        fclose(fh);
        return -1;
    }
    yaml_parser_set_input_file(&parser, fh);

    int current_key = 0;
    // key 映射枚举
    enum { NONE = 0, ROLE, KEY_FILE, SERVER_IP, SERVER_PORT, INTERFACE, 
           LOCAL_IP, REMOTE_IP, LOCAL_IP6, REMOTE_IP6, GW_IP, 
           BRUTAL_ENABLED, BRUTAL_RATE };

    while (1) {
        if (!yaml_parser_parse(&parser, &event)) break;
        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }

        if (event.type == YAML_SCALAR_EVENT) {
            char *val = (char *)event.data.scalar.value;
            
            // 解析 Key
            if (current_key == NONE) {
                if (strcmp(val, "role") == 0) current_key = ROLE;
                else if (strcmp(val, "key_file") == 0) current_key = KEY_FILE;
                else if (strcmp(val, "server_ip") == 0) current_key = SERVER_IP;
                else if (strcmp(val, "server_port") == 0) current_key = SERVER_PORT;
                else if (strcmp(val, "interface") == 0) current_key = INTERFACE;
                else if (strcmp(val, "local_tun_ip") == 0) current_key = LOCAL_IP;
                else if (strcmp(val, "remote_tun_ip") == 0) current_key = REMOTE_IP;
                else if (strcmp(val, "local_tun_ip6") == 0) current_key = LOCAL_IP6;
                else if (strcmp(val, "remote_tun_ip6") == 0) current_key = REMOTE_IP6;
                else if (strcmp(val, "gateway_ip") == 0) current_key = GW_IP;
                else if (strcmp(val, "enabled") == 0) current_key = BRUTAL_ENABLED;
                else if (strcmp(val, "rate_bytes") == 0) current_key = BRUTAL_RATE;
            } 
            // 解析 Value
            else {
                switch (current_key) {
                    case ROLE: ctx->is_server = (strcmp(val, "server") == 0); break;
                    case KEY_FILE: strncpy(ctx->key_file_buf, val, sizeof(ctx->key_file_buf)-1); break;
                    case SERVER_IP: strncpy(ctx->server_ip_or_name_buf, val, sizeof(ctx->server_ip_or_name_buf)-1); break;
                    case SERVER_PORT: strncpy(ctx->server_port_buf, val, sizeof(ctx->server_port_buf)-1); break;
                    case INTERFACE: strncpy(ctx->wanted_if_name_buf, val, sizeof(ctx->wanted_if_name_buf)-1); break;
                    case LOCAL_IP: strncpy(ctx->local_tun_ip_buf, val, sizeof(ctx->local_tun_ip_buf)-1); break;
                    case REMOTE_IP: strncpy(ctx->remote_tun_ip_buf, val, sizeof(ctx->remote_tun_ip_buf)-1); break;
                    case LOCAL_IP6: strncpy(ctx->local_tun_ip6_buf, val, sizeof(ctx->local_tun_ip6_buf)-1); break;
                    case REMOTE_IP6: strncpy(ctx->remote_tun_ip6_buf, val, sizeof(ctx->remote_tun_ip6_buf)-1); break;
                    case GW_IP: strncpy(ctx->wanted_ext_gw_ip_buf, val, sizeof(ctx->wanted_ext_gw_ip_buf)-1); break;
                    case BRUTAL_ENABLED: ctx->brutal_enabled = (strcmp(val, "true") == 0); break;
                    case BRUTAL_RATE: ctx->brutal_rate = strtoull(val, NULL, 10); break;
                }
                current_key = NONE; // 读完值后重置状态
            }
        }
        yaml_event_delete(&event);
    }
    
    yaml_parser_delete(&parser);
    fclose(fh);
    return 0;
}

int main(int argc, char *argv[])
{
    Context     context;
    const char *ext_gw_ip;

    if (argc < 2) {
        usage();
        return 1;
    }
    
    memset(&context, 0, sizeof context);

    // 1. 从 YAML 加载配置
    if (load_yaml_config(argv[1], &context) != 0) {
        fprintf(stderr, "Failed to parse config file.\n");
        return 1;
    }
	
    if (context.brutal_enabled) {
        printf("TCP Brutal: ENABLED (Rate: %llu bytes/s)\n", (unsigned long long)context.brutal_rate);
    } else {
        printf("TCP Brutal: DISABLED\n");
    }
    // ----------------------------------------

    // 2. 加载密钥文件
    if (context.key_file_buf[0] == '\0') {
        fprintf(stderr, "key_file is required in config.\n");
        return 1;
    }
    if (load_key_file(&context, context.key_file_buf) != 0) {
        fprintf(stderr, "Unable to load the key file [%s]\n", context.key_file_buf);
        return 1;
    }

    // 3. 处理默认值与指针绑定
    // 服务器 IP (客户端必填，服务端可选用于绑定)
    context.server_ip_or_name = (context.server_ip_or_name_buf[0] != '\0') ? context.server_ip_or_name_buf : NULL;
    if (context.server_ip_or_name == NULL && !context.is_server) {
        fprintf(stderr, "Client must specify server_ip in config.\n");
        return 1;
    }

    // 端口
    context.server_port = (context.server_port_buf[0] != '\0') ? context.server_port_buf : DEFAULT_PORT;
    
    // 网卡名
    context.wanted_if_name = (context.wanted_if_name_buf[0] != '\0' && strcmp(context.wanted_if_name_buf, "auto") != 0) ? context.wanted_if_name_buf : NULL;

    // 内网 IP (如果没有配置，使用原版的 DEFAULT 逻辑)
    context.local_tun_ip = (context.local_tun_ip_buf[0] != '\0' && strcmp(context.local_tun_ip_buf, "auto") != 0) 
                            ? context.local_tun_ip_buf 
                            : (context.is_server ? DEFAULT_SERVER_IP : DEFAULT_CLIENT_IP);
                            
    context.remote_tun_ip = (context.remote_tun_ip_buf[0] != '\0' && strcmp(context.remote_tun_ip_buf, "auto") != 0) 
                            ? context.remote_tun_ip_buf 
                            : (context.is_server ? DEFAULT_CLIENT_IP : DEFAULT_SERVER_IP);

    // 网关 IP
    context.wanted_ext_gw_ip = (context.wanted_ext_gw_ip_buf[0] != '\0' && strcmp(context.wanted_ext_gw_ip_buf, "auto") != 0) ? context.wanted_ext_gw_ip_buf : NULL;
    
    ext_gw_ip = context.wanted_ext_gw_ip ? context.wanted_ext_gw_ip : get_default_gw_ip();
    snprintf(context.ext_gw_ip, sizeof context.ext_gw_ip, "%s", ext_gw_ip == NULL ? "" : ext_gw_ip);
    
    if (ext_gw_ip == NULL && !context.is_server) {
        fprintf(stderr, "Unable to automatically determine the gateway IP\n");
        return 1;
    }

    if ((context.ext_if_name = get_default_ext_if_name()) == NULL && context.is_server) {
        fprintf(stderr, "Unable to automatically determine the external interface\n");
        return 1;
    }

    // 处理 IPv6 (结合之前修改的 get_tun6_addresses 逻辑)
    get_tun6_addresses(&context);

    // 4. 核心网络初始化
    context.tun_fd = tun_create(context.if_name, context.wanted_if_name);
    if (context.tun_fd == -1) {
        perror("tun device creation");
        return 1;
    }
    printf("Interface: [%s]\n", context.if_name);
    
    if (tun_set_mtu(context.if_name, DEFAULT_MTU) != 0) {
        perror("mtu");
    }

#ifdef __OpenBSD__
    pledge("stdio proc exec dns inet", NULL);
#endif

    context.firewall_rules_set = -1;
    if (context.server_ip_or_name != NULL &&
        resolve_ip(context.server_ip, sizeof context.server_ip, context.server_ip_or_name) != 0) {
        firewall_rules(&context, 0, 1);
        return 1;
    }

    if (context.is_server) {
        if (firewall_rules(&context, 1, 0) != 0) {
            return -1;
        }
#ifdef __OpenBSD__
        printf("\nAdd the following rule to /etc/pf.conf:\npass out from %s nat-to egress\n\n",
               context.remote_tun_ip);
#endif
    } else {
        firewall_rules(&context, 0, 1);
    }

    // 5. 启动事件循环
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (doit(&context) != 0) {
        return -1;
    }
    
    firewall_rules(&context, 0, 0);
    puts("Done.");

    return 0;
}
