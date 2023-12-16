/* Lua HTTPSC - a HTTPS library for Lua
 *
 * Copyright (c) 2016  chenweiqi
 *
 * The MIT License (MIT)
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <poll.h>


#define BUF_SZ      0x1000
#define MAX_RETRY   32
#define ERROR_FD    -1
#define HEADER_LMT  8192
#define TIMEOUT     3000
#define TIMEOUT_M   70000

static int openssl_init = !!NULL;

typedef struct {
    int is_init;
    int ssl_init;
    int is_async;
    int snd_tmo;
    int rcv_tmo;
    SSL_CTX *ctx;
} cutil_conf_t;

enum cutil_conn_st
{
    CONNECT_INIT = 1,
    CONNECT_SSL = 2,
    CONNECT_DONE = 3
};

typedef struct {
    int fd;
    SSL* ssl;
    int in_async;
    int header;
    enum cutil_conn_st status;
} cutil_fd_t;

static cutil_conf_t* fetch_config(lua_State *L) {
    cutil_conf_t* cfg;
    cfg = lua_touserdata(L, lua_upvalueindex(1));
    if (!cfg) {
        luaL_error(L, "unable to fetch cfg");
        return NULL;
    }

    if (!cfg->is_init) {
        luaL_error(L, "not inited");
        return NULL;
    }

    if (!cfg->ssl_init) {
        if (!openssl_init) {
            openssl_init = !NULL;
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
        }
        cfg->ssl_init = !NULL;
    }

    if (!cfg->ctx) {
        cfg->ctx = SSL_CTX_new(SSLv23_client_method());
        if (!cfg->ctx) {
            char buf[256];
            unsigned long err = ERR_get_error();
            ERR_error_string_n(err, buf, sizeof(buf));
            luaL_error(L, "unable to new ssl_ctx %s", buf);
            return NULL;
        }
    }

    return cfg;
}

static int _gc_fd(lua_State *L) {
    cutil_fd_t* fd_t = lua_touserdata(L, 1);
    SSL* ssl = fd_t->ssl;
    if (ssl) {
        fd_t->ssl = NULL;
        /*
         *    Possible error: 
         *    "error:140E0197:SSL routines:SSL_shutdown:shutdown while in init"
         *     error while attempting an SSL_shutdown?
         *
         *    OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         *    an SSL handshake, while previous versions always return 0.
         *    Avoid calling SSL_shutdown() if handshake wasn't completed.
         */
        if (!SSL_in_init(ssl))
            SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    int fd = fd_t->fd;
    if (fd != ERROR_FD) {
        fd_t->fd = ERROR_FD;
        close(fd);
    }
    return 0;
}

static int _connect_ssl(lua_State *L, cutil_fd_t* fd_t) {
    SSL* ssl = fd_t->ssl;
    int ret = SSL_connect(ssl);
    if (ret == 1) {
        if (fd_t->in_async) {
            SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        }

        return 0;
    }
    int err = errno;
    int sslerr = SSL_get_error(ssl, ret);
    ERR_clear_error();
    if (sslerr != SSL_ERROR_WANT_WRITE && sslerr != SSL_ERROR_WANT_READ ) {
        luaL_error(L, "connect error: %s (%d), ssl_error: %d", strerror(err), err, sslerr);
        return -1;
    }
    return 1;
}

static int lconnect(lua_State *L) {
    cutil_conf_t* cfg = fetch_config(L);
    if (!cfg) return 0;
    
    const char * addr = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);

    cutil_fd_t* fd_t = lua_newuserdata(L, sizeof(cutil_fd_t));
    if (!fd_t) {
        luaL_error(L, "create fd %s %d failed", addr, port);
        return 0;
    }
    fd_t->fd = ERROR_FD;
    fd_t->ssl = NULL;
    fd_t->status = CONNECT_INIT;
    fd_t->in_async = cfg->is_async;
    fd_t->header = 0;

    if (luaL_newmetatable(L, "https_socket")) {
        lua_pushcfunction(L, _gc_fd);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in my_addr;
    fd_t->fd = fd;

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_addr.s_addr = inet_addr(addr);
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);

    int ret;
    struct timeval timeo;
    timeo.tv_sec = cfg->snd_tmo / 1000;
    timeo.tv_usec = (cfg->snd_tmo % 1000) * 1000;
    socklen_t len = sizeof(timeo);
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, len);
    if (ret) {
        luaL_error(L, "set send timeout failed");
        return 0;
    }
    timeo.tv_sec = cfg->rcv_tmo / 1000;;
    timeo.tv_usec = (cfg->rcv_tmo % 1000) * 1000;
    ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, len);
    if (ret) {
        luaL_error(L, "set recv timeout failed");
        return 0;
    }

    if (fd_t->in_async) {
        int flag = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flag | O_NONBLOCK);
    }

    ret = connect(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));
    if (ret != 0) {
        if (errno != EINPROGRESS) {
            luaL_error(L, "connect %s %d failed", addr, port);
            return 0;
        }
    }

    SSL *ssl = SSL_new(cfg->ctx);
    if (!ssl) {
        luaL_error(L, "ssl_new error, errno = %d", errno);
        return 0;
    }
    fd_t->ssl = ssl;
    fd_t->status = CONNECT_SSL;
    SSL_set_fd(ssl, fd);

    ret = _connect_ssl(L, fd_t);
    if (!fd_t->in_async) {
        if (ret != 0) {
            luaL_error(L, "ssl_connect fail");
            return 0;
        }
        fd_t->status = CONNECT_DONE;
    }
    return 1;
}

static int lcheck_connect(lua_State *L) {
    cutil_conf_t* cfg = fetch_config(L);
    if (!cfg) return 0;
    cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
    if (!fd_t) {
        luaL_error(L, "fd error");
        return 0;
    }

    if (fd_t->status == CONNECT_SSL) {
        int ret = _connect_ssl(L, fd_t);
        if (ret != 0)
            return 0;
        fd_t->status = CONNECT_DONE;
    }

    if (fd_t->status == CONNECT_DONE) {
        lua_pushboolean(L, 1);
        return 1;
    }

    luaL_error(L, "connect error");
    return 0;
}

static int luseless(lua_State *L) {
    return 0;
}


static int lsend(lua_State *L) {
    cutil_conf_t* cfg = fetch_config(L);
    if (!cfg) return 0;
    
    cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
    if ( fd_t == NULL ) {
        luaL_error(L, "fd error");
        return 0;
    }
    if (fd_t->status != CONNECT_DONE) {
        luaL_error(L, "fd status error");
        return 0;
    }
    size_t sz = 0;
    const char * msg = luaL_checklstring(L, 2, &sz);
    if (sz <= 0) {
        lua_pushinteger(L, 0);
        return 1;
    }
    fd_t->header = 0;

    SSL* ssl = fd_t->ssl;
    int r = SSL_write(ssl, msg, (int)sz);
    if (r > 0) {
        lua_pushinteger(L, r);
        return 1;
    }
    if (errno == EAGAIN || errno == EINTR) {
        lua_pushinteger(L, 0);
        return 1;
    }
    int err = errno;
    int sslerr = SSL_get_error(ssl, r);
    ERR_clear_error();
    /*
     *    Possible error: 
     *    "error:1409F07F:SSL routines:SSL3_WRITE_PENDING: bad write retry" error
     *     while attempting an SSL_write?
     *
     *    For example, when SSL_write(ssl, ptr, size) with ptr = 0xABCDEFGH, 
     *    size = 4096 fails with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, 
     *    when retrying the SSL_write call, the parameters ptr and size should
     *    be same. It is not equivalent if ptr is another pointer pointing 
     *    to a copy of the same contents as in the original call.
     */
    luaL_error(L, "send error: %s (%d), ssl_error : %d", strerror(err), err, sslerr);
    return 0;
}


static int lrecv(lua_State *L) {
    cutil_conf_t* cfg = fetch_config(L);
    if (!cfg) return 0;

    cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
    if (!fd_t) {
        luaL_error(L, "fd error");
        return 0;
    }
    if (fd_t->status != CONNECT_DONE) {
        luaL_error(L, "fd status error");
        return 0;
    }

    char buffer[BUF_SZ];
    int size = BUF_SZ * MAX_RETRY;
    if (lua_gettop(L) > 1 && lua_isnumber(L, 2)) {
        int _size = lua_tointeger(L, 2);
        if (_size > 0)
            size = _size;
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    int bset = 0;
    int sz;
    SSL* ssl = fd_t->ssl;

    for (;;) {
        sz = size < BUF_SZ ? size : BUF_SZ;
        if (fd_t->header >= 0) {
            if (sz + fd_t->header > HEADER_LMT) {
                sz = HEADER_LMT - fd_t->header;
            }
        }
        
        int r = SSL_read(ssl, buffer, sz);
        if (r < 0) {
            int sslerr = SSL_get_error(ssl, r);
            ERR_clear_error();
            if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
                break;
            }
            luaL_error(L, "recv error: %d", sslerr);
            return 0;
        }
        if (r == 0)
            break;

        if (r > sz) {
            luaL_error(L, "recv overflow: %d", r);
            return 0;
        }

        bset = 1;
        luaL_addlstring(&b, (const char*)buffer, r);
        size -= r;

        if (fd_t->header >= 0) {
            fd_t->header += r;
            if (fd_t->header >= HEADER_LMT){
                fd_t->header = -1;
                break;
            }
        }
        if (size <= 0)
            break;
    }
    if (bset) {
        luaL_pushresult(&b);
        return 1;
    }
    return 0;
}


static int lusleep(lua_State *L) {
    int n = luaL_checknumber(L, 1);
    usleep(n);
    return 0;
}


/* GC, clean up the ctx */
static int _gc(lua_State *L) {
    cutil_conf_t* cfg = lua_touserdata(L, 1);
    SSL_CTX *ctx;
    if (cfg && (ctx = cfg->ctx)) {
        cfg->ctx = NULL;
        SSL_CTX_free(ctx);
    }
    return 0;
}

static void _create_config(lua_State *L) {
    cutil_conf_t *cfg;
    cfg = lua_newuserdata(L, sizeof(*cfg));
    cfg->is_init = !!NULL;
    cfg->ssl_init = !!NULL;
    cfg->ctx = NULL;
    cfg->is_async = !NULL;
    cfg->snd_tmo = TIMEOUT;
    cfg->rcv_tmo = TIMEOUT;
    /* Create GC to clean up ctx */
    lua_newtable(L);
    lua_pushcfunction(L, _gc);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);
    cfg->is_init = !NULL;
}

static int lset_conf(lua_State *L) {
    cutil_conf_t* cfg = fetch_config(L);
    if (!cfg) {
        return 0;
    }
    luaL_checktype(L, 1, LUA_TTABLE);

    /* load openssl libary */
    lua_getfield(L, 1, "init_lib");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TBOOLEAN);
        if (!lua_toboolean(L, -1))
            cfg->ssl_init = !NULL;
    }
    lua_pop(L, 1);

    /* set socket sync */
    lua_getfield(L, 1, "async");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TBOOLEAN);
        if (!lua_toboolean(L, -1))
            cfg->is_async = !!NULL;
    }
    lua_pop(L, 1);

    /* set socket send timeout */
    lua_getfield(L, 1, "send_timeout");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TNUMBER);
        int snd_tmo = lua_tointeger(L, -1);
        if (snd_tmo > 0)
            cfg->snd_tmo = snd_tmo < TIMEOUT_M ? snd_tmo : TIMEOUT_M;
    }
    lua_pop(L, 1);

    /* set socket recv timeout */
    lua_getfield(L, 1, "recv_timeout");
    if (!lua_isnil(L, -1)) {
        luaL_checktype(L, -1, LUA_TNUMBER);
        int rcv_tmo = lua_tointeger(L, -1);
        if (rcv_tmo > 0)
            cfg->rcv_tmo = rcv_tmo < TIMEOUT_M ? rcv_tmo : TIMEOUT_M;
    }
    lua_pop(L, 1);

    return 0;
}


int luaopen_httpsc(lua_State *L) {
    static const luaL_Reg funcs[] = {
        { "connect", lconnect },
        { "check_connect", lcheck_connect },
        { "recv", lrecv },
        { "send", lsend },
        { "set_conf", lset_conf },
        { "usleep", lusleep },
        /* useless */
        { "close", luseless },
        {NULL, NULL}
    };

    lua_newtable(L);
    _create_config(L);
    luaL_setfuncs(L, funcs, 1);

    return 1;
}