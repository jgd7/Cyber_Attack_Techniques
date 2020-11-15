local nmap = require "nmap"
local datetime = require "datetime"
local shortport = require "shortport"
local sslcert = require "sslcert"
local tls = require "tls"
local stdnse = require "stdnse"


description = [[Connect to a secure web server, retrieve the certificate and analysed if the certificate’s SubjectName (common name) or SubjectAltName.
Output a warning message if the certificate validity is more recent than a given date
]]
-- @usage
-- nmap -p 443 --script untrustedTLScerts --script-args "list = <suspicius_list>, date = <reference_date>" <ip>
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- untrustedTLScerts: 
-- subjectName: www.jg.com
-- subjectAltName: DNS:www.jg2.com, DNS:www.jg.es
-- suspiciusServers: 
-- 
-- 	certainty: 0.99
--	name: www.jg.com
--	severity: critical
--
--	certainty: 0.99
--	name: *.jg.com
--	severity: critical
-- validity: 
--	notBefore: 2020-11-09T09:57:03
--	notAfter: 2021-11-09T09:57:03
-- date_validity: The certificate date is valid

-- @args -- untrustedTLScerts.list the path to the file with the list of suspicius servers (default: list.csv)
--
-- @args -- untrustedTLScerts.date given date to compate against the certificate validity (default: os.time())


portrule = shortport.http


function ParseCSVLine (line,sep) 
	
	local pos = 1
	local counter = 0
	sep = sep or ','
	while true do 
		local c = string.sub(line,pos,pos)
		if (c == "") then break end	
		-- no quotes used, just look for the first separator
		local startp,endp = string.find(line,sep,pos)
		if (startp) then
			if(counter == 0) then
				name= string.sub(line,pos+1,startp-1)
				pos = endp + 1
				counter = counter +1
			
			else
				certainty = string.sub(line,pos,startp-1)
				pos = endp + 1
			end
			
		else
			-- no separator found -> use rest of string and terminate
			severity = string.sub(line,pos,#string -2)
			break
		end 
	end
	return name, certainty, severity
end


function extractDomain (subject)
	subdomain, domain =  subject:match"([^.]*).(.*)"
	return domain
end


function analyzeDomain(cert, file)
	
	subjectName = cert.subject.commonName
	subjectDomain = extractDomain(subjectName)

	for _, e in ipairs(cert.extensions) do
		if e.name == "X509v3 Subject Alternative Name" then
			subjectAltName = e.value
		break
		end
	end
	
	file = file or 'list.csv'

	local list = {}
	for line in io.lines(file) do
		name, certainty, severity = ParseCSVLine (line,';')
		nameDomain = extractDomain(name)
		
		if(subjectDomain == nameDomain) then
			list[#list + 1] = {name = name, certainty=certainty, severity=severity}
		end
		
		for dns in subjectAltName:gmatch("([^DNS:]+)") do
			dnsDomain = extractDomain(dns)
			
			if(subjectDomain == dnsDomain and subjectDomain ~= nameDomain) then
				list[#list + 1] = {name = name, certainty=certainty, severity=severity}
			end
	 	
		end
	end
	
	return subjectName, subjectAltName, list
end


function convertDateToTimestamp(date)
  
  local pattern = "(%d+)-(%d+)-(%d+)"
  local year, month, day = arg_date:match(pattern)
  local timestamp  = os.time({year = year, month = month, day = day})
  
  return timestamp

end


function analyzeDateValidity(validity, date)
  
  date = date or os.time()
  
  local timestamp  = convertDateToTimestamp(date)

  local timestampBefore  = convertDateToTimestamp(validity["NotBefore"])
  
  local timestampAfter  = convertDateToTimestamp(validity["NotAfter"])
  
  
  if(timestamp < timestampBefore) then
  	result = "The certificate date is more recent than the given date"
  else
  	result = "The certificate date is valid"
  end
  
  return result

end




action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)

  if (not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end
  
  arg_list = stdnse.get_script_args(SCRIPT_NAME..".list")
  arg_date = stdnse.get_script_args(SCRIPT_NAME..".date")
  
  subjectName, subjectAltName, result = analyzeDomain(cert, arg_list)
  
  o = stdnse.output_table()
  o.subjectName = subjectName
  o.subjectAltName = subjectAltName
  o.suspiciusServers = result
  
  o.validity = {}
  for k, v in pairs(cert.validity) do
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = datetime.format_timestamp(v)
    end
    
   o.date_validity = analyzeDateValidity(o.validity, arg_date)
   
  end
  
  return o

end