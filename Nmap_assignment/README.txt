Scanning with Nmap

@usage
-- nmap -p 443 --script untrustedTLScerts --script-args "list = /root/Documents/list.csv, date = 2021-11-10" 10.0.3.158

@output
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


Test perfomed:

 - Test main functionality using a certificate with SubjectName and 2 SubjectAltNames. The list of suspicius domains used includes:
 	- Domains with wildcards
 	- Domains present in the SubjectName or the SubjectAltNames
 	- Domains not present neither in SubjectName or the SubjectAltNames

 - Test date functionality with dates previous and posterior to the notBefore date.

