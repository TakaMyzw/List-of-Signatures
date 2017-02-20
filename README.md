List-of-Signatures
==================

Overview

Listing all of threat signatures of PANW Firewall with TSV(Tab Separated Value) format.

## Description

Although you are able to search and read information of threat signatures(vulnerability and phone home payload) on a PANW hosted website called ThreaVault as well as administrative console of the firewall, this script additonally allows you to download all information for viewing offline and editing your convenient way.

## Requirements:

* PAN-OS version: 8.0 or later with Threat Prevention subscription
* PANW Firewall appliance: all platforms, including VM series
* Application and Threat signature(A.K.A. weekly update) has to be installed in the firewall
* IP reachability between a host run this script and a firewall
* Openssl which supports ECC kind cipher
* Python 2.7 or above

## Usage

Options:
* -t {vul,ph} : Type of signature. vulnerability or phone home payload
* -f : Use API key instead of credential. This makes first authentication slightly faster
* -s : Simple output. see below
* -o : Write to a file instead of stdout

## Output Sample

vulnerability(simple):
```
Content Version : xxx-xxxx
Release Date : YYYY/MM/DD  HH:MM:SS
Total number of signatures : XXXX
-----
id	name
3000	Novell File Reporter Agent XML Tag Overflow Vulnerability
.......
```

vulnerability(detail):
```
Content Version : xxx-xxxx
Release Date : YYYY/MM/DD  HH:MM:SS
Total number of signatures : XXXX
-----
id	namey	severity	reference	cve	bugtraq	vendorID	description
30000	Novell File Reporter Agent XML Tag Overflow Vulnerability	high	http://www.zerodayinitiative.com/advisories/ZDI-11-116/	CVE-2011-0994......
.......
..
```

Note:
* This script may take more than 10 minute as it obtains all of descriptions which can only be gotten by "operational" command of API
* reference, cve, bugtraq and vendorID fields may have multiple items separated with a white space 
