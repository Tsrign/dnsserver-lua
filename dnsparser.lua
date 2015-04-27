local DNSParser = {}
DNSParser.__index = DNSParser

local recordTypes = {
	A = 1,
	AAAA = 28,-- IPv6
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15, -- Mail exchange (MX) record
	TXT = 16,
	["*"] = 255,
	AFSDB = 18,
	APL = 42,
	CAA = 257,
	CERT = 37,
	DHCID = 49,
	DLV = 32769,
	DNAME = 39,
	DNSKEY = 48,
	DS = 43,
	HIP = 55,
	IPSECKEY = 45,
	KEY = 25,
	KX = 36,
	LOC = 29,
	NAPTR = 35,
	NSEC = 47,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	RRSIG = 46,
	RP = 17,
	SIG = 24,
	SPF = 99,
	SRV = 33,
	SSHFP = 44,
	TA = 32768,
	TKEY = 249,
	TLSA = 52,
	TSIG = 250,
}

local classTypes = {
	IN = 1, -- the Internet
	CS = 2, -- the CSNET class (Obsolete)
	CH = 3, -- the CHAOS class
	HS = 4, -- Hesiod [Dyer 87]
	["*"] = 255,
}

function DNSParser.lshift(b, n)
	if n > 7 then
		return 0
	end
	b = b % (2 ^ (8-n))
	b = b * (2^n)
	return b
end

function DNSParser.rshift(b, n)
	if n > 7 then
		return 0
	end
	b = math.floor(b / (2^n))
	return b;
end

function DNSParser.int2char(n)
	local b1 = math.floor(n / (2^24))
	local b2 = math.floor((n-b1*(2^24)) / (2^16))
	local b3 = math.floor((n - b1*(2^24) - b2*(2^16)) / (2^8))
	local b4 = n  % (2^8)
	
	return string.char(b1, b2, b3, b4)
end

function DNSParser.short2char(n)
	local b1 = math.floor(n / (2^8))
	local b2 = n % (2^8)
	return string.char(b1, b2)
end

function DNSParser.byte2char(n)
	return string.char(n)
end

function DNSParser.domain2char(domain)
	-- add num
	domain = domain:gsub("[%w%-]+", function(s)
		return string.char(#s) .. s
	end)
	-- remove .
	domain = domain:gsub("%.", '')
	return domain
end

function DNSParser.ip2char(ip)
	ip = ip:gsub("[%d]+", function(s) 
		return string.char(s)
	end)

	ip = ip:gsub("%.", '')
	return ip
end

--assunming one byte
function DNSParser.sliceBits(b, n, l)
	if n+l > 9 then
		return nil
	end
	--b = b % (2^(8-n+1))
	--b = b * (2^(n-1))
	--b = math.floor(b / (2^(8-l)))
	b = DNSParser.lshift(b, 8-n+1)
	b = DNSParser.rshift(b, 8-l)
	return b
end

function DNSParser:parseByte()
	local pos = self.pos
	local buf = self.buf
	local byte = buf:byte(pos)
	self.pos = pos + 1
	return byte
end

function DNSParser:parseShort()
	local pos = self.pos
	local buf = self.buf
	local b2, b1 = buf:byte(pos, pos+1)
	self.pos = pos + 2
	return b2*(2^8)+b1	
end

function DNSParser:parseInt()
	local pos = self.pos
	local buf = self.buf
	local b4, b3, b2, b1 = buf:byte(pos, pos+3)
	self.pos = pos + 4
	return b4*(2^24) + b3*(2^16) + b2*(2^8) + b1
end


function DNSParser:parseHeader()
	local header = {}
	header.id = self:parseShort()
	local tmpbyte = self:parseByte()
	-- 1 bit
	header.qr = DNSParser.sliceBits(tmpbyte, 1, 1)
	-- opcode
	-- 0 = standard, 1 = inverse, 2 = server status, 3-15 reserved
	-- 4 bits
	header.opcode = DNSParser.sliceBits(tmpbyte, 2, 4)
	-- authorative answer
	-- 1 bit
	header.aa = DNSParser.sliceBits(tmpbyte, 6, 1)
	-- truncated
	-- 1bit
	header.tc = DNSParser.sliceBits(tmpbyte, 7, 1)
	-- recursion desired
	-- 1 bite
	header.rd = DNSParser.sliceBits(tmpbyte, 8, 1)
	tmpbyte = self:parseByte()
	-- recursion available
	-- 1 bit
	header.ra = DNSParser.sliceBits(tmpbyte, 1, 1)
	-- reserved 3 bits
	header.z = DNSParser.sliceBits(tmpbyte, 2, 3)
	-- response code
	-- 0 = no error, 1 = format error, 2 = server failure
	-- 3 = name error, 4 = not implemented, 5 = refused
	--  6-15 reserved
	-- 4bits
	header.rcode = DNSParser.sliceBits(tmpbyte, 4, 4)
	
	-- question count
	-- 2 byte
	header.qdcount = self:parseShort()
	-- answer count
	-- 2byte
	header.ancount = self:parseShort()
	-- ns count
	-- 2byte
	header.nscount = self:parseShort()
	-- addtional resources count
	-- 2byte
	header.arcount = self:parseShort()
	
	return header
end

function DNSParser:parseDomainName()
	local nextbyte = self:parseByte() 
	local domain = {}
	while nextbyte > 0 do
		domain[#domain + 1] = self.buf:sub(self.pos, self.pos+nextbyte-1)
		self.pos = self.pos + nextbyte
		nextbyte = self:parseByte()
	end
	return table.concat(domain, '.') 

end

function DNSParser:parseQuestion(n)
	local questions = {}
	for i=1, n do
		local qname = self:parseDomainName()	
		local qtype = self:parseShort()
		local qclass = self:parseShort()
		questions[#questions + 1] = {
			qname = qname,
			qtype = qtype,
			qclass = qclass
		}
	end
	return questions
end

function DNSParser:parseAnswer(n)
	local answers = {}
	for i=1, n do
		local aname = self:parseDomainName()
		local atype = self:parseShort()
		local aclass = self:parseShort()
		local attl = self:parseInt()
		local ardlength = self:parseShort()
		local arddata = self.buf:sub(self.pos, self.pos+ardlength)
		self.pos = self.pos + ardlength
		anwsers[#answers + 1] = {
			aname = aname,
			atype = atype,
			aclass = aclass,
			attl = attl,
			ardlength = ardlength,
			arddata = arddata
		}
	end
	return {}
end

function DNSParser.parse(buf)
	local parser = setmetatable({buf=buf, pos=1}, DNSParser)
	local header = parser:parseHeader()
	local questions = parser:parseQuestion(header.qdcount)
	local answers = parser:parseAnswer(header.ancount)
	return {
		header = header,
		questions = questions,
		answers = answers
	}
end

--return reponse packet
function DNSParser.response(response)
	local buf = ""
	buf = buf .. DNSParser.short2char(response.header.id)
	buf = buf .. DNSParser.byte2char(response.header.qr * (2^7) + response.header.opcode * (2^3) + response.header.aa * (2^2) + response.header.tc * (2^1) + response.header.rd)
	buf = buf .. DNSParser.byte2char(response.header.ra * (2^7) + response.header.z * (2^4) + response.header.rcode)
	buf = buf .. DNSParser.short2char(response.header.qdcount)
	buf = buf .. DNSParser.short2char(response.header.ancount)
	buf = buf .. DNSParser.short2char(response.header.nscount)
	buf = buf .. DNSParser.short2char(response.header.arcount)

	for i=1, #response.questions do
		local question = response.questions[i]
		buf = buf .. DNSParser.domain2char(question.qname) .. string.char(0)
		buf = buf .. DNSParser.short2char(question.qtype)
		buf = buf .. DNSParser.short2char(question.qclass)
	end

	for i=1, #response.answers do
		local answer = response.answers[i]
		buf = buf .. DNSParser.domain2char(answer.aname) .. string.char(0)
		buf = buf .. DNSParser.short2char(answer.atype)
		buf = buf .. DNSParser.short2char(answer.aclass)
		buf = buf .. DNSParser.int2char(answer.attl)
		buf = buf .. DNSParser.short2char(answer.ardlength)
		buf = buf .. DNSParser.ip2char(answer.ardata)
	end
	return buf

end

return DNSParser
