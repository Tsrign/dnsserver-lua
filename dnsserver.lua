--[[
-- Require: luasocket or nixio.socket
-- Author: Tsrign
--]]

package.path = package.path .. ';/usr/local/share/lua/5.1/?.lua;'    --搜索lua模块
package.cpath = package.cpath .. ';/usr/local/lib/lua/5.1/?.so;'        --搜索so模块

local socket = require "socket"
local dns = require "dnsparser" 
local debugswitch = false

--print(dns.new("aa"):sliceBits(15, 5, 2))

function debug(...)
	if debugswitch then
		print(unpack(arg))
	end
end

function send(...)
	return coroutine.yield(unpack(arg))
end

function receive(daemon, ...)
	return coroutine.resume(daemon, unpack(arg))
end

function listener()
	return coroutine.create(function()
		local proxy = socket.udp()
		proxy:settimeout(0)
		debug('proxy bind...')
		assert(proxy:setsockname('*', 53))
		while true do
			local rawdata, ip, port = proxy:receivefrom()
			debug("listener receive")
			local rawobj = {}
			if rawdata and #rawdata > 0 then
				rawobj = {
					rawdata = rawdata,
					ip = ip,
					port = port
				}
			end
			response = send(rawobj)
			
			-- if return from parent, maybe ""
			if response.rawdata then
				debug("listener sen rawdata to ", response.ip, response.port)
				proxy:sendto(response.rawdata, response.ip, response.port)
			end
		end
	end)
end

function parser(daemon)
	return coroutine.create(function()
		local response = {}
		while true do
			local status, rawobj = receive(daemon, response)
			if status then
				local query = {}
				if rawobj.rawdata  then
					query = dns.parse(rawobj.rawdata)
					query.ip = rawobj.ip
					query.port = rawobj.port
					query.rawdata = rawobj.rawdata
					debug("parser query seq id:", query.header.id)
				end
				response = send(query)
				if response.header and response.header.id then
					debug("parser response seq id:", response.header.id)
					response = {
						rawdata = dns.response(response),
						ip = response.ip,
						port = response.port
					}
				end
			end
		end
	end)
end

function filter(daemon)
	return coroutine.create(function() 
		local response = {}
		while true do
			local status, query = receive(daemon, response)
			--filter action for ip, port or rawdata
			if query.header and query.header.id then
				debug("filter for query: ", query.header.id)	
				-- action
			end

			if status then
				-- input filter action
				debug("filter send")
				response =  send(query)
				debug("filter receive", response)
				if response.header and response.header.id then
					-- output filter action
					--filter action for ip, port or rawdata
					debug("filter for response: ", response.header.id)
				end
			end
		end
	end)
end


function forwarder(daemon)
	return coroutine.create(function()
		local response = {} 
		local taskqueue = {}
		local busy = false
		local tmpsocket = socket.udp()
		-- non block for asynchronous
		tmpsocket:settimeout(0)
		tmpsocket:setsockname("*", 0)
		while true do
			local status, query = receive(daemon, response)
			respone = {}
			if not status then
				print("forwarder last level error")
				os.exit()
			end
			if query.header and  query.header.id then
				debug("forwarder send")
				response = send(query)
				-- query remote server
				if not response.header then
					-- join queue
					taskqueue[#taskqueue + 1] = query
					-- select a task
					if not busy and #taskqueue > 0 then
						for i=0, #taskqueue do
							if taskqueue[i] then
								busy = taskqueue[i]
								tmpsocket:sendto(busy.rawdata, "114.114.114.114", 53)
								taskqueue[i] = nil
							end
						end
					end
				end
			else
				if busy then
					local data = tmpsocket:receive()
					if data and #data > 0 then
						response = dns.parse(data)
						response.ip = busy.ip
						response.port = busy.port
					end
				end

			end
		end
	end)
end

function responser(daemon)
	local response = {} 
	while true do
		local status, query = receive(daemon, response)
		response = {}
		if not status then
			print("responser last level error")
			os.exit()
		end
		if query.header and query.header.id then
			--response = response ..
			response = {
				header = {},
				questions = {},
				answers = {}
			}
			-- 2byte
			response.header.id = query.header.id
			-- combined 1byte
			response.header.qr = 1 -- this is a response
			response.header.opcode = 0
			response.header.aa = 0
			response.header.tc = 0
			response.header.rd = 1

			--combined 1byte
			response.header.ra = 0
			response.header.z = 0
			response.header.rcode = 0

			--1byte
			response.header.qdcount = query.header.qdcount
			response.header.ancount = 1
			response.header.nscount = 0
			response.header.arcount = 0

			response.questions = query.questions

			response.answers = {}
			response.answers[1] = {
				aname = query.questions[1]['qname'],
				atype = 1,
				aclass = 1,
				attl = 1,
				ardlength = 4,
				ardata = "106.184.3.40" 
			}
			response.ip = query.ip
			response.port = query.port
			--response = {}
			print("resolve: ", query.questions[1]['qname'])
		end
	end	
end


responser(forwarder(filter(parser(listener()))))
