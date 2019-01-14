# lua_httpsc
An asynchronous https library for lua


## API
```lua
local httpsc = require "httpsc"
```

### Connect remote https server
```lua
local ip = "127.0.0.1"
local port = 443

local fd = httpsc.connect(ip, port)
-- Check connection
while true do
	local ok = httpsc.check_connect(fd)
	if ok then break end
	httpsc.usleep(10000)
end
```
### Write data to remote
```lua
-- It is asynchronous now
httpsc.send(fd, msg)
```

### Receive data from remote
```lua
httpsc.recv(fd)
```

### Close Connection
```lua
-- Actually, it's useless. Because close is auto executed by LUA GC
httpsc.close(fd)
```

## Example
See test.lua

## Defect
Only single-threaded support now
