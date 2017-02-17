import sys
import csv
import argparse
import xml.etree.ElementTree as ET
import httplib
import urllib
import urllib2
import ssl
import cookielib
import re
import os
from urllib2 import Request, urlopen, URLError, HTTPError

# skip server certificate validation
if hasattr(ssl, '_create_unverified_context'):
	ssl._create_default_https_context = ssl._create_unverified_context

keylist = './keylist.txt'
sessionkey = 0

parser = argparse.ArgumentParser(description='List of all threat signatures(Vulnerability or PhoneHome)')

parser.add_argument('-t', action="store", type=str, choices=['vul', 'ph'], help='Type of signature');
parser.add_argument('-f', action='store_true', help='Use key file keylist.txt to skip user/password authentication')
parser.add_argument('-s', action='store_true', help='Get simple output includes only threat ID and threat name')
parser.add_argument('-o', help='write to a file instead of stdout. Specify a filename')
parser.add_argument('hostname', action="store", default=False, help='PANW Firewall hostname')

args = parser.parse_args()
#print parser.parse_args()

if args.t == 'vul':
	threat_type = 'vulnerability'
else:
	threat_type = 'phone-home'

fw_url = 'https://' + args.hostname + '/api/?'

print fw_url

# Key generation

def keygen(url):
	print "generate a new key"
	params_keygen = urllib.urlencode({'type': 'keygen', 'user': 'admin', 'password': 'admin'})
	print params_keygen
 
	try: 
		response_keygen = urllib2.urlopen(url, params_keygen, 10).read()
	except URLError, e:
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server couldn\'t fulfill the request.'
			print 'Error code: ', e.code
		sys.exit(1)
	else:
		key_tree = ET.fromstring(response_keygen)
		if key_tree.get('status') == "success":
			return key_tree.find('result/key').text
		else:
			print response_sysinfo
			sys.exit(1)

# list file processing
if args.o:
	try:
		f_list = open(args.o, 'w+')
	except IOError:
		print >> sys.stderr, 'cannot open "%s"' % iofile
		sys.exit(1)


# key file processing
if args.f:
	try:
		f = open(keylist, 'a+')
		try:
			f.seek(0,0)
			reader = csv.DictReader(f,["host","key"])
			for row in reader:
				if row['host'] == args.hostname:
					print "key for the host found in keylist.txt. use existing key."
					sessionkey = row['key']
			if not sessionkey:
				sessionkey = keygen(fw_url)
				writer = csv.writer(f)
				writer.writerow( (args.hostname,sessionkey))
		finally:
			f.close()
	except IOError:
		print >> sys.stderr, 'cannot open "%s"' % iofile
		sys.exit(1)
else:
	sessionkey = keygen(fw_url)


params_systeminfo = urllib.urlencode({'type': 'op', 'key': sessionkey, 'cmd': '<show><system><info></info></system></show>' })

try:
	response_sysinfo = urllib2.urlopen(fw_url, params_systeminfo, 10).read()
except URLError, e:
	if hasattr(e, 'reason'):
		print 'We failed to reach a server.'
		print 'Reason: ', e.reason
	elif hasattr(e, 'code'):
		print 'The server couldn\'t fulfill the request.'
		print 'Error code: ', e.code
	sys.exit(1)
except HTTPError, e:
	if hasattr(e, 'reason'):
		print 'We failed to reach a server.'
		print 'Reason: ', e.reason
	elif hasattr(e, 'code'):
		print 'The server couldn\'t fulfill the request.'
		print 'Error code: ', e.code
	sys.exit(1)
else:

	sysinfo_tree = ET.fromstring(response_sysinfo)
	if sysinfo_tree.get('status') == "success":
		threat_version = sysinfo_tree.find('result/system/threat-version').text
		threat_date = sysinfo_tree.find('result/system/threat-release-date').text

		if args.o:
			f_list.write("Content Version : {0}\n".format(threat_version))
			f_list.write("Release Date : {0}\n".format(threat_date))
			
		else:
			print ("Content Version : {0}".format(threat_version))
			print ("Release Date : {0}".format(threat_date))
	else:
		print response_sysinfo
		sys.exit(1)

# fetch all signatures only ID and name
params_signature = urllib.urlencode({'type': 'config', 'key': sessionkey, 'action': 'get', 'xpath': '/config/predefined/threats/' + threat_type })
try:
	response_sig = urllib2.urlopen(fw_url, params_signature, 10).read()
except URLError, e:
	if hasattr(e, 'reason'):
		print 'We failed to reach a server.'
		print 'Reason: ', e.reason
	elif hasattr(e, 'code'):
		print 'The server couldn\'t fulfill the request.'
		print 'Error code: ', e.code
	sys.exit(1)
else:

#	print response_sig

	sig_tree = ET.fromstring(response_sig)
	xpath = 'result/' + threat_type + '/entry'
	if args.o:
		f_list.write("Total number of signatures : {0}\n-----\n".format(len(sig_tree.findall(xpath))))
	else:
		print ("Total number of signatures : {0}".format(len(sig_tree.findall(xpath))))
		print ("-----")
	if threat_type == 'vulnerability':
		if args.o:
			if args.s:
				f_list.write("id\tname\n")
			else:
				f_list.write("id\tnamey\tseverity\treference\tcve\tbugtraq\tvendorID\tdescription\n")
		else:
			if args.s:
				print "id\tname"
			else:
				print "id\tnamey\tseverity\treference\tcve\tbugtraq\tvendorID\tdescription"
	else:
		if args.o:
			if args.s:
				f_list.write("id\tname\n")
			else:
				f_list.write("id\tname\tseverity\treference\tdescription\n")
		else:
			if args.s:
				print "id,name,severity,category,default-action"
			else:
				print "id,name,severity,category,default-action,description"

# sort
	container = sig_tree
	data = []
	for elem in container.findall(xpath):
		key = elem.get('name')
		data.append((key, elem))
	data.sort()
	container[:] = [item[-1] for item in data]

# fetch detailed information of each signature items

	for element in container:
		id = element.get('name')
		name = element.find('threatname').text

		if args.s:
			print("{0}\t{1}".format(id,name))
		else:
			params_detail = urllib.urlencode({'type': 'op', 'key': sessionkey, 'cmd': '<show><threat><id>' + id + '</id></threat></show>' })
			try:
				response_detail = urllib2.urlopen(fw_url, params_detail , 10).read()
			except URLError, e:
				if hasattr(e, 'reason'):
					print 'We failed to reach a server.'
					print 'Reason: ', e.reason
				elif hasattr(e, 'code'):
					print 'The server couldn\'t fulfill the request.'
					print 'Error code: ', e.code
				sys.exit(1)
			else:
				reference = ""
#				print response_detail
				detail_tree = ET.fromstring(response_detail)
				if detail_tree.get('status') == "success":
					desc_raw = detail_tree.find('result/entry/description').text.strip()
					description = desc_raw.replace('\n', ' ')
					severity = detail_tree.find('result/entry/severity').text
					reference_tree = detail_tree.find('result/entry/reference');
					if reference_tree is None :
						reference = ''
					else:
						c = 0
						for m in reference_tree:
							if c == 0:
								reference = reference + m.text
							else:
								reference = reference + " " + m.text
							c += 1
				else:
					print response_detail

			cve = ""
			vendor = ""
			bugtraq = ""

			if threat_type == 'vulnerability':
#				print ("{0},{1}".format(id,detail_tree.findall('result/entry/vulnerability/cve')))
				cve_tree = detail_tree.find('result/entry/vulnerability/cve');
				if cve_tree is None :
					cve = ''
				else:
					c = 0
					for m in cve_tree:
						if c == 0:
							cve = cve + m.text
						else:
							cve = cve + " " + m.text
						c += 1
				vendor_tree = detail_tree.find('result/entry/vulnerability/vendor');
				if vendor_tree is None :
					vendor = ''
				else:
					c = 0
					for m in vendor_tree:
						if c == 0:
							vendor = vendor + m.text
						else:
							vendor = vendor + " " + m.text
						c += 1
				bugtraq_tree = detail_tree.find('result/entry/vulnerability/bugtraq');
				if bugtraq_tree is None :
					bugtraq = ''
				else:
					c = 0
					for m in bugtraq_tree:
						if c == 0:
							bugtraq = bugtraq + m.text
						else:
							bugtraq = bugtraq + " " + m.text
						c += 1

#				print id,cve,vendor,bugtraq
				if args.o:
					if args.s:
						f_list.write("{0}\t{1}\n".format(id,name))
					else:
						f_list.write("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\n".format(id,name,severity,reference,cve,bugtraq,vendor,description))

				else:
					if args.s:
						print("{0}\t{1}".format(id,name))
					else:
						print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\n".format(id,name,severity,reference,cve,bugtraq,vendor,description))

			else:
				if args.o:
					if args.s:
						f_list.write("{0}\t{1}\n".format(id,name))
					else:
						f_list.write("{0}\t{1}\t{2}\t{3}\t{4}\n".format(id,name,severity,reference,description))

				else:
					if args.s:
						print("{0}\t{1}".format(id,name))
					else:
						print("{0}\t{1}\t{2}\t{3}\t{4}\n".format(id,name,severity,reference,description))
				


if args.o:
	f_list.close()
sys.exit(0)
