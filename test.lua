local httpsc = require "httpsc"
local internal = require "internal"

local fd = httpsc.connect("104.193.88.77", 443)
while true do
	local ok = httpsc.check_connect(fd)
	if ok then break end
	httpsc.usleep(10000)
end
-- print(fd)
local request = internal.request(httpsc, fd)
local code, body = request("GET", "www.baidu.com", "/", nil, {}, nil)
print("http code",code)
print("body length",#body)
print("done!")

httpsc = nil
request = nil
package.loaded["httpsc"] = nil
package.preload["httpsc"] = nil
collectgarbage()
collectgarbage()

local httpsc = require "httpsc"

local fd = httpsc.connect("104.193.88.77", 443)
while true do
	local ok = httpsc.check_connect(fd)
	if ok then break end
	httpsc.usleep(10000)
end
local request = internal.request(httpsc, fd)
local code, body = request("GET", "www.baidu.com", "/", nil, {}, nil)
print("http code",code)
print("body length",#body)
print("done!")
