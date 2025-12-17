local httpsc = require "httpsc"
local internal = require "internal"

local function check_protocol(host)
	local protocol = host:match("^[Hh][Tt][Tt][Pp][Ss]?://")
	if protocol then
		host = string.gsub(host, "^"..protocol, "")
		protocol = string.lower(protocol)
		if protocol == "https://" then
			return "https", host
		elseif protocol == "http://" then
			return "http", host
		else
			error(string.format("Invalid protocol: %s", protocol))
		end
	else
		return "http", host
	end
end

local function http_request(method, host, url, recvheader, header, content)
	local protocol
	protocol, host = check_protocol(host)
	local hostaddr, port = host:match"([^:]+):?(%d*)$"
	if port == "" then
		port = protocol=="http" and 80 or protocol=="https" and 443
	else
		port = tonumber(port)
	end
	local fd = httpsc.connect(hostaddr, port, protocol)
	while true do
		local ok = httpsc.check_connect(fd)
		if ok then break end
		httpsc.usleep(10000)
	end
	local interface = {}
	function interface.read(sz)
		local body = ""
		while true do
			local data = httpsc.recv(fd, sz)
			if data then
				body = body .. data
				sz = (sz or 0) - #data
				if sz <= 0 then
					break
				end
			end
			httpsc.usleep(10000)
		end
		return body
	end
	function interface.write(data)
		while true do
			local sz = httpsc.send(fd, data)
			if sz then
				data = data:sub(sz + 1)
				if #data == 0 then
					break
				end
			end
			httpsc.usleep(10000)
		end
	end
	local ok , statuscode, body , header = pcall(internal.request, interface, method, host, url, recvheader, header, content)
	if ok then
		ok, body = pcall(internal.response, interface, statuscode, body, header)
	end
	return statuscode, body
end

-- nonblocking example
print("GET https://www.baidu.com")
local code, body = http_request("GET", "https://www.baidu.com", "/")
print(code, body and #body)

print("GET http://www.baidu.com")
local code, body = http_request("GET", "http://www.baidu.com", "/")
print(code, body and #body)

print("GET https://api.iplocation.net/?ip=8.8.8.8")
local code, body = http_request("GET", "https://api.iplocation.net", "/?ip=8.8.8.8")
print(code, body and #body)


-- blocking example
httpsc.set_conf({async = false})

print("GET blocking https://www.baidu.com")
local code, body = http_request("GET", "https://www.baidu.com", "/")
print(code, body and #body)

print("GET blocking https://api.iplocation.net/?ip=8.8.8.8")
local code, body = http_request("GET", "https://api.iplocation.net", "/?ip=8.8.8.8")
print(code, body and #body)

-- gc
httpsc = nil
request = nil
package.loaded["httpsc"] = nil
package.preload["httpsc"] = nil
collectgarbage()
collectgarbage()


