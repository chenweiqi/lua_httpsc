# lua_httpsc
A non-blocking https client library for lua, it also support http request

## Require
openssl >= 1.0.1
lua >= 5.3


## API
```lua
httpsc = require "httpsc"
```

### Connect remote https server
```lua
local host = "www.baidu.com"
local port = 443

fd = httpsc.connect(host, port)  -- default https
-- fd = httpsc.connect(host, port, "http")
-- fd = httpsc.connect(host, port, "https")
```


### Check connection is ready, only for non-blocking request
```lua
-- Check connection
while true do
	local ok = httpsc.check_connect(fd)
	if ok then break end
	httpsc.usleep(10000)
end
```

### Write data to remote
```lua
httpsc.send(fd, msg)
```

### Receive data from remote
```lua
httpsc.recv(fd, size)       -- size is optional
```


### Set configure
```lua
httpsc.set_conf({
	init_lib = true,	-- load openssl libary, default: true
	async = true,		-- work under non-blocking, default: true
	send_timeout = 10000,	-- socket send timeout, default: 10000 (10 second)
	recv_timeout = 10000,	-- socket recv timeout, default: 10000 (10 second)
})
```

## Example
See test.lua

