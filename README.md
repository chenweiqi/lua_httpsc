# lua_httpsc
An asynchronous https client library for lua


## API
```lua
httpsc = require "httpsc"
```

### Connect remote https server
```lua
local ip = "127.0.0.1"
local port = 443

fd = httpsc.connect(ip, port)
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
	init_lib = true, 		-- load openssl libary, default: true
	async = true,			-- work under non-blocking, default: true
	send_timeout = 3000,	-- socket send timeout, default: 3000 (3 second)
	recv_timeout = 3000,	-- socket recv timeout, default: 3000 (3 second)
})
```

## Example
See test.lua

