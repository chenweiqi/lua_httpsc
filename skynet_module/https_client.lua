local skynet = require "skynet"
require "skynet.manager"
local httpsc = require "httpsc"
local internal = require "http.internal"
local dns = require "dns"

local retry_time = 20      -- 超时重试次数
local retry_time_base = 5  -- 多久(单位0.1秒)重试一次
local timeout = 15         -- 连接超时(单位1秒)
local timeout_connect = 3  -- 创建连接超时(单位1秒)
local read_wait = 10       -- 读不到数据时的等待时间(单位0.01秒)，让出调度权


local requests = {}
local connections = {}

local command = {}

local req_step = {
    start = 1,
    doing = 2,
    finish = 3,
    error = 4,
}

local function logger_msg(msg_type, format, ...)
    skynet.error(string.format("[%s %s] ".. format, os.date("%Y-%m-%d %H:%M:%S"), msg_type, ...))
end

local logger = {
    info = function( ... )
        logger_msg("info", ...)
    end,
    err = function( ... )
        logger_msg("error", ...)
    end
}

local host_cache = {}
local function getip(host, is_fresh)
    if not is_fresh and host_cache[host] then
        return host_cache[host]
    end
    local ip, ips = dns.resolve(host)
    for k,v in ipairs(ips) do
        if host_cache[host] ~= v then
            host_cache[host] = v
            break
        end
    end
    return host_cache[host]
end

local function handle_err(e)
    e = debug.traceback(coroutine.running(), tostring(e), 2)
    skynet.error(e)
    return e
end

local function recv_data(request)
    if request.step >= req_step.finish then
        error("Invalid Step")
    end
    local read = function(size)
        local data = httpsc.recv(request.fd, size)
        if not data then
            skynet.sleep(read_wait)
        end
        return data or ""
    end

    if request.step == req_step.doing then
        local length = request.length
        local body = request.body
        local padding = read(length - #body)
        body = body .. padding
        if #body >= length then
            request.body = body:sub(1,length)
            request.step = req_step.finish
            return
        else
            request.body = body
        end
    else
        request.step = req_step.doing

        local code, body
        local tmpline = {}
        local body = internal.recvheader(read, tmpline, "")
        if not body then
            error("Socket error")
        end

        local statusline = tmpline[1]
        local code, info = statusline:match "HTTP/[%d%.]+%s+([%d]+)%s+(.*)$"
        code = assert(tonumber(code))
        request.code = code

        local recvheader
        local header = internal.parseheader(tmpline,2,recvheader or {})
        if not header then
            error("Invalid HTTP response header")
        end

        local length = header["content-length"]
        if length then
            length = tonumber(length)
            request.length = length
        end

        local mode = header["transfer-encoding"]
        if mode then
            if mode ~= "identity" and mode ~= "chunked" then
                error ("Unsupport transfer-encoding")
            end
        end

        if mode == "chunked" then
            body, header = internal.recvchunkedbody(read, nil, header, body)
            if not body then
                error("Invalid response body")
            end
            request.step = req_step.finish
        else
            -- identity mode
            
            if length then
                if #body >= length then
                    body = body:sub(1,length)
                else
                    local padding = read(length - #body)
                    body = body .. padding
                end
                if #body >= length then
                    request.body = body
                    request.step = req_step.finish
                    return
                end
            else
                request.body = nil
                request.step = req_step.finish
                return
            end
        end
        request.body = body
    end
end

local function finish_request(requests, request, ret, step)
    pcall(httpsc.close, request.fd)
    if request.co then
        request.ret = ret
        request.step = step
        requests[request.co] = nil
        xpcall(skynet.wakeup, handle_err, request.co)
    end
end

local function do_timeout()
    local interval = 2*100
    while true do
        skynet.sleep(interval)
        local now = os.time()
        for co, request in pairs(requests) do
            if now - request.time > timeout then
                finish_request(requests, request, "connect timeout", req_step.error)
            end
        end
        for co, connection in pairs(connections) do
            if now - connection.time > timeout_connect then
                connections[co] = nil
                connection.error = "connecting timeout"
                pcall(httpsc.close, connection.fd)
                skynet.wakeup(co)
            end
        end
    end
end

local function do_clean()
    local interval = 5*60*100
    while true do
        skynet.sleep(interval)
        skynet.send(skynet.self(), "debug", "GC")
    end
end

local function do_connect()
    while true do
        while next(connections) do
            for co, connection in pairs(connections) do
                local ok, is_ok = pcall(httpsc.check_connect, connection.fd)
                if ok then
                    if is_ok then
                        connections[co] = nil
                        skynet.wakeup(co)
                    end
                else
                    connection.error = is_ok or "check_connect fail"
                    connections[co] = nil
                    skynet.wakeup(co)
                end
            end
            skynet.sleep(1)
        end
        skynet.sleep(10)
    end
end

local function request(fd, method, host, url, header, content)

    local write = function(msg)
        httpsc.send(fd, msg)
    end

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

    if content then
        local data = string.format("%s %s HTTP/1.1\r\n%scontent-length:%d\r\n\r\n%s", method, url, header_content, #content, content)
        write(data)
    else
        local request_header = string.format("%s %s HTTP/1.1\r\n%scontent-length:0\r\n\r\n", method, url, header_content)
        write(request_header)
    end

    return true
end


local function raw_request(method, host, url, header, content)
    local hostname, port = host:match"([^:]+):?(%d*)$"
    if port == "" then
        port = 443
    else
        port = tonumber(port)
    end
    --get ip of the host
    local svrip = getip(hostname, false)
    local ok, fd
    if svrip then
        ok, fd = pcall(httpsc.connect, svrip, port)
    else
        ok, fd = nil, "getip nil"
    end
    if not ok then --if conn fail, retry once
        if svrip ~= hostname then
            logger.err("https_client raw_request connect fail, will retry once, error = %s", fd)
            --resolve host again
            svrip = getip(hostname, true)
            if svrip then
                ok, fd = pcall(httpsc.connect, svrip, port)
            else
                ok, fd = nil, "refreship nil"
            end
        end
    end
    if not ok then
        logger.err("https_client raw_request connect fail, err = %s", fd)
        return false, fd
    end

    local self_co = coroutine.running()
    local connection = {
        fd = fd,
        time = os.time(),
    }
    connections[self_co] = connection
    skynet.wait()
    if connection.error then
        return false, connection.error
    end

    --perform request
    local ok = xpcall(request, handle_err, fd, method, host, url, header, content)
    if not ok then
        pcall(httpsc.close, fd)
        return false
    end
    
    return true, fd
end

local function raw_read(request)
    local retry_time_s = retry_time_base * 10
    for k =1, retry_time do
        local ok, err = pcall(recv_data, request)
        if not ok then
            logger.err("https_client recv data fail, err = %s", err)
            finish_request(requests, request, "recv_data error", req_step.error)
            return
        end
        if request.step >= req_step.finish then
            finish_request(requests, request, request.body, request.step)
            return
        end
        skynet.sleep(retry_time_s)
    end
    finish_request(requests, request, "recv_data timeout", req_step.error)
end

--- 请求某个url
-- @treturn bool 请求是否成功
-- @treturn string 当成功时，返回内容，当失败时，返回出错原因 
function command.request(method, host, url, header, content)
    local ok, is_ok, fd = xpcall(raw_request, handle_err, method, host, url, header, content)
    if not ok then
        logger.err("https_client request fail, host = %s, url = %s, err = %s", host, url, is_ok)
        return false, "request connection fail"
    end
    if not is_ok then
        logger.err("https_client request fail 2, host = %s, url = %s, err = %s", host, url, fd)
        return false, "request connection fail 2"
    end

    local self_co = coroutine.running()

    local request = {
        step = req_step.start,
        co = self_co,
        time = os.time(),
        fd = fd,
    }
    requests[self_co] = request
    skynet.fork(raw_read, request)
    skynet.wait()
    request.co = nil
    request.fd = nil

    if request.step ~= req_step.finish then
        logger.err("https_client request timeout, host = %s, url = %s, err = %s", host, url, request.ret)
        return false, request.ret or "request timeout"
    end

    return true, request.ret, request.code
end

local function escape(s)
    return (string.gsub(s, "([^A-Za-z0-9_])", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

function command.get(host, url)
    return command.request("GET", host, url, {}, "")
end

function command.post(host, url, form)
    local header = {
        ["content-type"] = "application/x-www-form-urlencoded"
    }
    local body = {}
    for k,v in pairs(form) do
        table.insert(body, string.format("%s=%s",escape(k),escape(v)))
    end
    return command.request("POST", host, url, header, table.concat(body , "&"))
end

local function lua_docmd(cmdhandler, session, cmd, ...)
	local f = cmdhandler[cmd]
	if not f then
		return error(string.format("%s Unknown command %s", SERVICE_NAME, tostring(cmd)))
	end
	if session == 0 then
		return f(...)
	else
		return skynet.ret(skynet.pack(f(...)))
	end
end


skynet.start(function()
    logger.info("https_client starting...")

    print("nameserver:", dns.server())  -- set nameserver

    skynet.fork(do_connect)
    skynet.fork(do_timeout)
    skynet.fork(do_clean)

    skynet.dispatch("lua", function (session, source, cmd, ...)
        return lua_docmd(command, session, string.lower(cmd), ...)
    end)


    skynet.register ".https_client"
    logger.info("https_client started!")
end)
