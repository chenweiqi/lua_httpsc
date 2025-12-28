local httpsc = require "httpsc"
local internal = require "internal"
local connect_pools
local http_request
local bench_request



local function main()

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

	-- gc
	httpsc = nil
	package.loaded["httpsc"] = nil
	package.preload["httpsc"] = nil
	connect_pools = nil
	collectgarbage()
	collectgarbage()

	httpsc = require "httpsc"

	-- blocking example
	httpsc.set_conf({async = false})

	print("GET blocking https://www.baidu.com")
	local code, body = http_request("GET", "https://www.baidu.com", "/")
	print(code, body and #body)

	print("GET blocking https://api.iplocation.net/?ip=8.8.8.8")
	local code, body = http_request("GET", "https://api.iplocation.net", "/?ip=8.8.8.8")
	print(code, body and #body)

	httpsc = nil
	package.loaded["httpsc"] = nil
	package.preload["httpsc"] = nil
	connect_pools = nil
	collectgarbage()
	collectgarbage()
	httpsc = require "httpsc"

	local sites = {
		-- "www.baidu.com",
		"www.qq.com",
		"www.163.com",
		"www.bing.com",
		"www.sina.com.cn",
	}

	local test_times = 20
	-- test 1: not use pools, use dns resolve
	print("bench test 1 start")
	local use_pool = false
	local use_times = bench_request(sites, use_pool, test_times)
	print(string.format("bench finish, use %s seconds", use_times))
	
	-- test 2: use pools, use dns resolve
	print("bench test 2 start")
	local use_pool = true
	local use_times = bench_request(sites, use_pool, test_times)
	print(string.format("bench finish, use %s seconds", use_times))

	-- test 2: use pools, use ip map
	print("bench test 3 start")
	local use_pool = true
	for _s, site in pairs(sites) do
		local ip = httpsc.dns_resolve(site)
		if ip then
			httpsc.set_ip(site, ip)
		end
	end
	local use_times = bench_request(sites, use_pool, test_times)
	print(string.format("bench finish, use %s seconds", use_times))
end

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

function http_request(method, host, url, recvheader, header, content)
	local protocol
	protocol, host = check_protocol(host)
	local hostaddr, port = host:match"([^:]+):?(%d*)$"
	if port == "" then
		port = protocol=="http" and 80 or protocol=="https" and 443
	else
		port = tonumber(port)
	end

	local pool_key = string.format("%s:%s:%s", hostaddr, port, protocol)
	connect_pools = connect_pools or {}
	local fd = connect_pools[pool_key]
	if fd then
		local ok = httpsc.check_connect(fd)
		if not ok then
			connect_pools[pool_key] = nil
			fd = nil
		end
	end
	if not fd then
		fd = httpsc.connect(hostaddr, port, protocol)
		while true do
			local ok = httpsc.check_connect(fd)
			if ok then break end
			httpsc.usleep(1000)
		end
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
			httpsc.usleep(1000)
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
			httpsc.usleep(1000)
		end
	end

	if not header then
		header = {}
	end
	header["Connection"] = "keep-alive"
	local ok, statuscode, body, header = pcall(internal.request, interface, method, host, url, recvheader, header, content)
	if ok then
		ok, body = pcall(internal.response, interface, statuscode, body, header)
	end
	if header["Connection"] ~= "close" then
		connect_pools[pool_key] = fd
	end

	return statuscode, body
end

function bench_request(sites, use_pool, test_times)
	local start_time = os.time()
	for _k = 1, test_times do
		for _s, site in pairs(sites) do
			if not use_pool then
				connect_pools = nil
			end
			local code, body = http_request("GET", "https://"..site, "/")
			if type(code) ~= "number" then
				print(string.format("site fail: %s, err %s", site, code))
			end
		end
	end
	return os.time() - start_time
end

main()

