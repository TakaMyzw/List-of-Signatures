import sys
import csv
import argparse
import xml.etree.ElementTree as ET
import httplib
import urllib
import urllib2
import re
import os
from urllib2 import Request, urlopen, URLError, HTTPError

keylist = './keylist.txt'
sessionkey = 0

parser = argparse.ArgumentParser(description='List of all threat signatures(Vulnerability or PhoneHome)')

parser.add_argument('-t', action="store", type=str, choices=['vul', 'ph'], help='Type of signature');
parser.add_argument('-f', action='store_true', help='Use key file keylist.txt to skip user/password authentication')
parser.add_argument('-o', help='write to a file instead of stdout. Specify a filename')
parser.add_argument('hostname', action="store", default=False, help='PANW Firewall hostname')

args = parser.parse_args()
#print parser.parse_args()

if args.t == 'vul':
	threat_type = 'vulnerability'
else:
	threat_type = 'phone-home'

fw_url = 'https://' + args.hostname + '/api/?'

# Key generation

def keygen(url):
#	print "generate a new key"
	params_keygen = urllib.urlencode({'type': 'keygen', 'user': 'admin', 'password': 'admin'})
 
	try: 
		response_keygen = urllib2.urlopen(url, params_keygen, 10).read()
	except URLError, e:
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server couldn\'t fulfill the request.'
			print 'Error code: ', e.code
	else:
		key_tree = ET.fromstring(response_keygen)
#		if sysinfo_tree.get('status') == "success":
		if key_tree.get('status') == "success":
			return key_tree.find('result/key').text
		else:
			print response_sysinfo
			sys.exit(1)

# list file processing
if args.o:
#	if os.path.exists(args.o):
#		exit(1)
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
#				print row
				if row['host'] == args.hostname:
					print "key for the host found in keylist.txt. use existing key."
					sessionkey = row['key']
			if not sessionkey:
				sessionkey = keygen(fw_url)
				writer = csv.writer(f)
				writer.writerow( (args.hostname,sessionkey))
#				print "added new key for the host in the file."
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
#	print response_sysinfo
except URLError, e:
	if hasattr(e, 'reason'):
		print 'We failed to reach a server.'
		print 'Reason: ', e.reason
	elif hasattr(e, 'code'):
		print 'The server couldn\'t fulfill the request.'
		print 'Error code: ', e.code
except HTTPError, e:
	if hasattr(e, 'reason'):
		print 'We failed to reach a server.'
		print 'Reason: ', e.reason
	elif hasattr(e, 'code'):
		print 'The server couldn\'t fulfill the request.'
		print 'Error code: ', e.code
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

# signature list
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
			f_list.write("id\tname\tseverity\tcategory\tdefault-action\taffected-host\tcve#\tvendorID\tdescription\n")
		else:
			print "id\tname\tseverity\tcategory\tdefault-action\taffected-host\tcve#\tvendorID\tdescription"
	else:
		if args.o:
			f_list.write("id\tname\tseverity\tcategory\tdefault-action\tdescription\n")
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

#	for element in sig_tree.findall(xpath):
	for element in container:
		id = element.get('name')
		name = element.find('threatname').text
		severity = element.find('severity').text
		category = element.find('category').text

# get description
		params_des = urllib.urlencode({'type': 'op', 'key': sessionkey, 'cmd': '<show><threat><id>' + id + '</id></threat></show>' })
		try:
			response_des = urllib2.urlopen(fw_url, params_des , 10).read()
		except URLError, e:
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason: ', e.reason
			elif hasattr(e, 'code'):
				print 'The server couldn\'t fulfill the request.'
				print 'Error code: ', e.code
		else:
#			print response_des
			des_tree = ET.fromstring(response_des)
			if des_tree.get('status') == "success":
				desc_raw = des_tree.find('result/entry/description').text.strip()
				description = desc_raw.replace('\n', ' ')
#				threat_date = sysinfo_tree.find('result/system/threat-release-date').text

#				print description
			else:
				print response_des
				sys.exit(1)
#

		if element.find('default-action') is None :
			d_act = ''
		else :
			d_act = element.find('default-action').text
		if threat_type == 'vulnerability':
			if element.find('cve/member') is None :
				cve = ''
			else:
				cve = element.find('cve/member').text
			if element.find('vendor/member') is None :
				vendor = ''
			else:
				vendor = element.find('vendor/member').text
			if element.find('affected-host/server') is None:
				if element.find('affected-host/client').text == 'yes':
					affect = 'client'
			elif element.find('affected-host/client') is None:
				if element.find('affected-host/server').text == 'yes':
					affect = 'server'
			else:
				affect = ''
			
			if args.o:
				f_list.write("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\n".format(id,name,severity,category,d_act,affect,cve,vendor,description))
			else:
				print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}".format(id,name,severity,category,d_act,affect,cve,vendor,description))
		else:
			if args.o:
				f_list.write("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n".format(id,name,severity,category,d_act,description))
			else:
				print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(id,name,severity,category,d_act,description))


if args.o:
	f_list.close()
exit(0)
