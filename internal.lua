local table = table
local type = type

local M = {}

local LIMIT = 8192

local function chunksize(readbytes, body)
	while true do
		local f,e = body:find("\r\n",1,true)
		if f then
			return tonumber(body:sub(1,f-1),16), body:sub(e+1)
		end
		if #body > 128 then
			-- pervent the attacker send very long stream without \r\n
			return
		end
		body = body .. readbytes()
	end
end

local function readcrln(readbytes, body)
	if #body >= 2 then
		if body:sub(1,2) ~= "\r\n" then
			return
		end
		return body:sub(3)
	else
		body = body .. readbytes(2-#body)
		if body ~= "\r\n" then
			return
		end
		return ""
	end
end

function M.recvheader(readbytes, lines, header)
	if #header >= 2 then
		if header:find "^\r\n" then
			return header:sub(3)
		end
	end
	local result
	local e = header:find("\r\n\r\n", 1, true)
	if e then
		result = header:sub(e+4)
	else
		while true do
			local bytes = readbytes()
			header = header .. bytes
			if #header > LIMIT then
				return
			end
			e = header:find("\r\n\r\n", -#bytes-3, true)
			if e then
				result = header:sub(e+4)
				break
			end
			if header:find "^\r\n" then
				return header:sub(3)
			end
		end
	end
	for v in header:gmatch("(.-)\r\n") do
		if v == "" then
			break
		end
		table.insert(lines, v)
	end
	return result
end

function M.parseheader(lines, from, header)
	local name, value
	for i=from,#lines do
		local line = lines[i]
		if line:byte(1) == 9 then	-- tab, append last line
			if name == nil then
				return
			end
			header[name] = header[name] .. line:sub(2)
		else
			name, value = line:match "^(.-):%s*(.*)"
			if name == nil or value == nil then
				return
			end
			name = name:lower()
			if header[name] then
				local v = header[name]
				if type(v) == "table" then
					table.insert(v, value)
				else
					header[name] = { v , value }
				end
			else
				header[name] = value
			end
		end
	end
	return header
end

function M.recvchunkedbody(readbytes, bodylimit, header, body)
	local result = ""
	local size = 0

	local sz
	while true do
		if sz then
			body = body .. readbytes(sz - #body)
			if #body >= sz then
				result = result .. body:sub(1,sz)
				body = body:sub(sz+1)
				body = readcrln(readbytes, body)
				if not body then
					return
				end
				sz = nil
			end
		end

		if not sz then
			sz , body = chunksize(readbytes, body)
			if not sz then
				return
			end
			if sz == 0 then
				break
			end
		end
	end

	local tmpline = {}
	body = M.recvheader(readbytes, tmpline, body)
	if not body then
		return
	end

	header = M.parseheader(tmpline,1,header)

	return result, header
end

function M.request(httpsc, fd)
	local function read(sz)
		return httpsc.recv(fd, sz) or ""
	end
	local function write(msg)
		while true do
			local send_len = httpsc.send(fd, msg)
			if send_len > 0 then
				if send_len >= #msg then
					break
				end
				msg = msg:sub(send_len+1)
			else
				httpsc.usleep(1000)
			end
		end
	end

	return function(method, host, url, recvheader, header, content)
		local header_content = ""
		if header then
			if not header.host then
				header.host = host
			end
			for k,v in pairs(header) do
				header_content = string.format("%s%s:%s\r\n", header_content, k, v)
			end
		else
			header_content = string.format("host:%s\r\n",host)
		end

		local data
		if content then
			data = string.format("%s %s HTTP/1.1\r\n%scontent-length:%d\r\n\r\n%s", method, url, header_content, #content, content)
		else
			data = string.format("%s %s HTTP/1.1\r\n%scontent-length:0\r\n\r\n", method, url, header_content)
		end
		-- print(#data)
		-- print(data)
		write(data)
		--httpsc.usleep(1000000)
		local tmpline = {}
		local body = M.recvheader(read, tmpline, "")
		if not body then
			error("socket_error")
		end

		local statusline = tmpline[1]
		local code, info = statusline:match "HTTP/[%d%.]+%s+([%d]+)%s+(.*)$"
		code = assert(tonumber(code))

		local header = M.parseheader(tmpline,2,recvheader or {})
		if not header then
			error("Invalid HTTP response header")
		end

		local length = header["content-length"]
		if length then
			length = tonumber(length)
		end

		local mode = header["transfer-encoding"]
		if mode then
			if mode ~= "identity" and mode ~= "chunked" then
				error ("Unsupport transfer-encoding")
			end
		end

		if mode == "chunked" then
			body, header = M.recvchunkedbody(read, nil, header, body)
			if not body then
				error("Invalid response body")
			end
		else
			-- print(length)
			if length then
				if #body >= length then
					body = body:sub(1,length)
				else
					while true do
						local padding = read(length - #body)
						if #padding>0 then
							body = body .. padding
							if #body>= length then
								body = body:sub(1,length)
								break
							end
						else
							httpsc.usleep(1000)
						end
					end
				end
			else
				body = nil
			end
		end
		return code, body
	end
end

return M
