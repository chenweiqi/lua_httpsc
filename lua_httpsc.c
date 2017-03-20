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


#define CACHE_SIZE 0x1000

static SSL_CTX *ctx = NULL;

typedef struct {
	int is_init;
} cutil_conf_t;

typedef struct {
	int fd;
	SSL* ssl;
} cutil_fd_t;

static cutil_conf_t* fetch_config(lua_State *L)
{
	cutil_conf_t* cfg;
	cfg = lua_touserdata(L, lua_upvalueindex(1));
	if (!cfg)
		luaL_error(L, "httpsc: Unable to fetch cfg");

	return cfg;
}

static int lconnect(lua_State *L) {
	cutil_conf_t* cfg = fetch_config(L);
	if(!cfg->is_init)
	{
		luaL_error(L, "httpsc: Not inited");
		return 0;
	}
	
	const char * addr = luaL_checkstring(L, 1);
	int port = luaL_checkinteger(L, 2);
	int fd = socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in my_addr;

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_addr.s_addr=inet_addr(addr);
	my_addr.sin_family=AF_INET;
	my_addr.sin_port=htons(port);

	int r = connect(fd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr_in));

	if (r == -1) {
		return luaL_error(L, "httpsc: Connect %s %d failed", addr, port);
	}
	
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		return luaL_error(L, "httpsc: Connect ssl %s %d failed", addr, port);
	}
	
	int flag = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flag | O_NONBLOCK);
	
	cutil_fd_t* fd_t = (cutil_fd_t *)malloc(sizeof(cutil_fd_t));
	if ( fd_t == NULL )
		return luaL_error(L, "httpsc: Connect fd %s %d failed", addr, port);
	
	fd_t->fd = fd;
	fd_t->ssl = ssl;
	lua_pushlightuserdata(L, fd_t);

	return 1;
}

static int lclose(lua_State *L) {
	cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
	if ( fd_t == NULL || ((cutil_fd_t*)fd_t)->fd == NULL)
		luaL_error(L, "httpsc fd error");
	
	SSL* ssl = fd_t->ssl;
	SSL_shutdown(ssl);
	SSL_free(ssl);
	
	int fd = fd_t->fd;
	close(fd);

	return 0;
}

static void block_send(lua_State *L, SSL *ssl, const char * buffer, int sz) {
	while(sz > 0) {
		int r = SSL_write(ssl, buffer, sz);
		if (r < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			luaL_error(L, "httpsc: socket error: %s", strerror(errno));
		}
		buffer += r;
		sz -= r;
	}
}

static int lsend(lua_State *L) {
	cutil_conf_t* cfg = fetch_config(L);
	if(!cfg->is_init)
	{
		luaL_error(L, "httpsc: Not inited");
		return 0;
	}
	
	size_t sz = 0;
	cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
	if ( fd_t == NULL)
		luaL_error(L, "httpsc fd error");
	SSL* ssl = fd_t->ssl;
	const char * msg = luaL_checklstring(L, 2, &sz);

	block_send(L, ssl, msg, (int)sz);

	return 0;
}


static int lrecv(lua_State *L) {
	cutil_conf_t* cfg = fetch_config(L);
	if(!cfg->is_init)
	{
		luaL_error(L, "httpsc: Not inited");
		return 0;
	}
	cutil_fd_t* fd_t = (cutil_fd_t* ) lua_touserdata(L, 1);
	if ( fd_t == NULL )
		luaL_error(L, "httpsc fd error");
	SSL* ssl = fd_t->ssl;

	char buffer[CACHE_SIZE];
	int r = SSL_read(ssl, buffer, CACHE_SIZE);
	if (r == 0) {
		lua_pushliteral(L, "");
		// close
		return 1;
	}
	if (r < 0) {
		if (errno == EAGAIN || errno == EINTR) {
			return 0;
		}
		luaL_error(L, "httpsc: socket error: %s", strerror(errno));
	}
	lua_pushlstring(L, buffer, r);
	return 1;
}


static int lusleep(lua_State *L) {
	int n = luaL_checknumber(L, 1);
	usleep(n);
	return 0;
}


/* GC, clean up the buf */
static int _gc(lua_State *L)
{
	cutil_conf_t *cfg;
	cfg = lua_touserdata(L, 1);

	if (ctx != NULL){
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	
	// todo: auto gc

	cfg = NULL;
	return 0;
}

static void _create_config(lua_State *L)
{
	cutil_conf_t *cfg;
	cfg = lua_newuserdata(L, sizeof(*cfg));
	cfg->is_init = NULL;
	/* Create GC method to clean up buf */
	lua_newtable(L);
	lua_pushcfunction(L, _gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);

	/* openssl init */
	if ( ctx == NULL) {
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		ctx = SSL_CTX_new(SSLv23_client_method());
		if (ctx == NULL)
		{
			ERR_print_errors_fp(stdout);
			luaL_error(L, "httpsc: Unable to init openssl");
			return;
		}
	}

	cfg->is_init = !NULL;
}


int luaopen_httpsc(lua_State *L)
{
	static const luaL_Reg funcs[] = {
		{ "connect", lconnect },
		{ "recv", lrecv },
		{ "send", lsend },
		{ "close", lclose },
		{ "usleep", lusleep },
		{NULL, NULL}
	};

	lua_newtable(L);
	_create_config(L);
	luaL_setfuncs(L, funcs, 1);

	return 1;
}