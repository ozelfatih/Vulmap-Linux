#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#==========================================================================
# LIBRARIES python2.x
#==========================================================================
import json
import string
import urllib
import urllib2
import argparse
import subprocess

__version__ = 1.0

#==========================================================================
# GLOBAL VARIABLES
#==========================================================================
tempList = []
productList = []

#==========================================================================
# CLASSES
#==========================================================================

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

#==========================================================================
# FUNCTIONS
#==========================================================================
def header():
	print "###################################################################"
	print "                                                               	  "
	print "██╗        ██╗   ██╗██╗   ██╗██╗     ███╗   ███╗ █████╗ ██████╗    "
	print "╚██╗       ██║   ██║██║   ██║██║     ████╗ ████║██╔══██╗██╔══██╗   "
	print " ╚██╗      ██║   ██║██║   ██║██║     ██╔████╔██║███████║██████╔╝   "
	print " ██╔╝      ╚██╗ ██╔╝██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝ 	  "
	print "██╔╝███████╗╚████╔╝ ╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║     	  "
	print "╚═╝ ╚══════╝ ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝    	  "
	print "			    						                                              "
	print "###################################################################"
	print "Vulmon Mapper v1.0"
	print "\n"

def args():
	global args

	desc = """
	Find latest vulnerabilities and exploits on local host.
	"""
	epilog = """
	Examples:
	Use %(prog)s to get vulnerabilities and exploits that affects the host.
	Use %(prog)s to -d <exploit_id> to download a specific exploit.
	Use %(prog)s -a to download all found exploits.
	Use %(prog)s -v for verbose mode.
	"""

	parser = argparse.ArgumentParser('vulmap.py', description=desc, epilog=epilog)
	parser.add_argument('-v', '--verbose', action="store_true", default=False, help='Verbose mode', dest='verbose', required=False)

	parser.add_argument('-a', '--download_all', action="store_true", default=False, help='Download all found exploits', dest='exploit', required=False)

	parser.add_argument('-d', '--download', type=str, dest='exploit_ID', help='Download a specific exploit ./%(prog)s -d EDB16372', required=False)

	parser.add_argument('--version', action='version', version='%(prog)s version v' + str(__version__))

	args = parser.parse_args()


def getDistroInfo():
	command = "cat /etc/*release | grep ID"
	action = subprocess.Popen(command, shell = True, stdout = subprocess.PIPE)

	results = action.communicate()[0].split('\n')

	for i in range(0, len(results)-1):
		a = results[i].split("=")
		if a[0]=='ID':
			ID = "ID: " + a[1] + " "
		if a[0]=='VERSION_ID':
			VERSION = "VERSION: " + str(a[1]).strip('"')
	print ID 
	print VERSION 


def getKernelInfo():
	command = "uname -mrs"

	action = subprocess.Popen(command, shell = True, stdout = subprocess.PIPE)

	results = action.communicate()[0].split(" ")

	print "SYSTEM: " + results[0]
	print "VERSION: " + results[1]
	print "ARCHITECTURE: " + results[2]

	
def getProductList_dpkg():
	global tempList
	global productList
	command = "dpkg-query -W -f='${Package} ${Version}\n'"
	
	action = subprocess.Popen(command, shell = True, stdout = subprocess.PIPE)

	results = action.communicate()[0]
		
	tempList = results.split("\n")

	for i in range(0,len(tempList)-1):
		productList.append(tempList[i].split(" "))

def getProductList_rpm():
	global tempList
	global productList

	command = "rpm -qa --qf '%{NAME} %{VERSION}\n'"
	
	action = subprocess.Popen(command, shell = True, stdout = subprocess.PIPE)

	results = action.communicate()[0]
		
	tempList = results.split("\n")

	for i in range(0,len(tempList)-1):
		productList.append(tempList[i].split(" "))


def parseProductList_dpkg():
	global productList
	for i in range(0,len(productList)):
		productList[i][0] = (string.replace(productList[i][0], '-','_').replace(':','_').replace('.','_')).lower()


def parseProductList_rpm():
	global productList
	for i in range(0,len(productList)):
		productList[i][0] = string.replace(productList[i][0], '-','_').lower()


def vulnerabilityCheck_verbose():
	global productList
	print "[Info] Verbose mode, scan starting..."
	for i in range(0,len(productList)):
		product = str(productList[i][0])
		version = str(productList[i][1])
	
		url = "http://vulmon.com/scannerapi?product=" + product + "&version=" + version
	
		try:
			data = json.load(urllib2.urlopen(url))
		except Exception, e:
			print "Internet, not connection!\n"
			break
		if data["totalHits"]:
			if data["totalHits"]:
				print ""
				print bcolors.OKGREEN + "[*]" + bcolors.ENDC + " Vulnerability Found!"
				print bcolors.OKGREEN + "[>]" + bcolors.ENDC + " Product: " + product + " " + version
			for i in range(0, len(data["results"])):
				print bcolors.OKGREEN + "[+]" + bcolors.ENDC + " CVEID: " + data["results"][i]["CVEID"] + "	" + "Score: " + str(data["results"][i]["CVSSv2BaseScore"]) + "	" + "URL: " + data["results"][i]["url"]

				try:
					if data["results"][i]["exploits"]:
						print bcolors.FAIL + "	[*]" + bcolors.ENDC + " Available Exploits!!!"
						for j in range(0, len(data["results"][i]["exploits"])):
							exploit_url = data["results"][i]["exploits"][j]["url"]
							edb_id = exploit_url.split("=")
							print bcolors.FAIL + "	[!]" + bcolors.ENDC + " Exploit ID: " + edb_id[1] + " URL: " + str(data["results"][i]["exploits"][j]["url"]) + " (" + data["results"][i]["exploits"][j]["title"] +")"
				except Exception, e:
					continue
			print ""
 		else:
 			print bcolors.WARNING + "[-]" + bcolors.ENDC + " Product: " + product + " " + version
	
	print "STATE: SCAN END!"


def vulnerabilityCheck():
	global productList
	print "[Info] Normally mode, scan starting..."
	for i in range(0,len(productList)):
		product = str(productList[i][0])
		version = str(productList[i][1])
	
		url = "http://vulmon.com/scannerapi?product=" + product + "&version=" + version
		
		try:
			data = json.load(urllib2.urlopen(url))
		except Exception, e:
			print "Internet, not connection!"
			break
		
		if data["totalHits"]:
			print bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Vulnerability Found!"
			print bcolors.OKGREEN + "[>]" + bcolors.ENDC + " Product: " + product + " " + version
			for i in range(0, len(data["results"])):
				print bcolors.OKGREEN + "[+]" + bcolors.ENDC + " CVEID: " + data["results"][i]["CVEID"] + "	" + "Score: " + str(data["results"][i]["CVSSv2BaseScore"]) + "	" + "URL: " + data["results"][i]["url"]

				try:
					if data["results"][i]["exploits"]:
						print bcolors.FAIL + "	[*] " + bcolors.ENDC +"Available Exploits!!!"
						for j in range(0, len(data["results"][i]["exploits"])):
							exploit_url = data["results"][i]["exploits"][j]["url"]
							edb_id = exploit_url.split("=")
							print bcolors.FAIL + "	[!]" + bcolors.ENDC + " Exploit ID: " + edb_id[1] + " URL: " + str(data["results"][i]["exploits"][j]["url"]) + " (" + data["results"][i]["exploits"][j]["title"] +")"
				except Exception, e:
					continue

			print ""

	print "STATE: SCAN END!"


def exploitDownload(exploit_id):
	try:
		url = "http://www.vulmon.com/downloadexploit?qid=" + exploit_id
		EDB = url.split("=")
		print "[Info] Exploit downloading..."
		urllib.urlretrieve(url, ("Exploit_" + EDB[1]))
		print bcolors.FAIL + "	[*] " + bcolors.ENDC +"Exploit Downloaded!"
		print bcolors.FAIL + "	[!] " + bcolors.ENDC + "Make use of Exploit ID: " + EDB[1]
	except Exception, e:
		print "Internet, not connection!"

def exploitDownload_all():
	global productList
	print "[Info] All exploits downloading..."
	for i in range(0,len(productList)):
		product = str(productList[i][0])
		version = str(productList[i][1])

		url = "http://vulmon.com/scannerapi?product=" + product +"&version="+ version
		try:
			data = json.load(urllib2.urlopen(url))
		except Exception, e:
			print "Internet, not connection!"
			break
		
		if data["totalHits"]:	
			for k in range(0,len(data["results"])):
				try:
					if data["results"][k]["exploits"]:
						print bcolors.FAIL + "	[+] " + bcolors.ENDC + "Product: " + product + " " + version
						for j in range(0, len(data["results"][k]["exploits"])):
							exploit_url = data["results"][k]["exploits"][j]["url"]

							edb_id = exploit_url.split("=")
							url = 'http://www.vulmon.com/downloadexploit?qid=' + edb_id[1]
							urllib.urlretrieve(url, ("Exploit_" + edb_id[1] + "_" + product + "_" + version))

							print bcolors.FAIL + "	[!] " + bcolors.ENDC + "Exploit ID: " + edb_id[1]
				except Exception, e:
					continue
				print ""


#==========================================================================
# MAIN PROGRAM
#==========================================================================

header()
args()

try:
	getProductList_dpkg()
	parseProductList_dpkg()
except Exception, e:
	getProductList_rpm()
	parseProductList_rpm()

if args.verbose:
	getDistroInfo()
	getKernelInfo()
	vulnerabilityCheck_verbose()
elif args.exploit_ID:
	exploitDownload(args.exploit_ID)
elif args.exploit:
	exploitDownload_all()
else:
	getDistroInfo()
	getKernelInfo()
	vulnerabilityCheck()
