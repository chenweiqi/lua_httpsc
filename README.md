# lua_httpsc
A non-blocking https client library for lua, it also support blocking request, http request


## API
```lua
httpsc = require "httpsc"
```

### Connect remote https server
```lua
local ip = "127.0.0.1"
local port = 443

fd = httpsc.connect(ip, port)
-- fd = httpsc.connect(ip, port, "http")
-- fd = httpsc.connect(ip, port, "https")
```


### Check connection is ready, only for async
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

