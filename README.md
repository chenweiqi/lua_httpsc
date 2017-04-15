# lua_httpsc
An asynchronous https library for lua

## API
local httpsc = require "httpsc"

### Connect remote https server
local ip = "127.0.0.1"
local fd = httpsc.connect(ip, 443)

-- Check connection
while true do
	local ok = httpsc.check_connect(fd)
	if ok then break end
	httpsc.usleep(10000)
end

### Write data to remote

-- It is still synchronous and will be optimized in the future
httpsc.send(fd, msg)


### Receive data from remote
httpsc.recv(fd)


### Close Connection
httpsc.close(fd)


## Example
See test.lua