#!/usr/bin/env python2
#
# Reputation database downloader and updater
#
# based on code by aortega@alienvault.com
# borja@libcrack.so.com
#

import os
import sys
import pycurl
import StringIO
import time
import re

from logger import Logger
logger = Logger.logger

rep_serv = "https://reputation.alienvault.com/"

rep_file = "reputation.data"
rep_rev = "reputation.rev"

global log_file
log_file = "reputation.log"

global curlrc
curlrc = "/etc/curlrc"

def check_reputation_format(data):
	r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
	for ln in data.split("\n"):
		if ln != "":
			if not r.match(ln):
				return False
	return True

def get_url(url):
	try:
		buffer = StringIO.StringIO()
		c = pycurl.Curl()
		c.setopt(pycurl.URL, url)
		c.setopt(pycurl.SSL_VERIFYPEER, 0)
		c.setopt(pycurl.WRITEFUNCTION, buffer.write)
		c.perform()
		rcode = c.getinfo(pycurl.HTTP_CODE)
		data = buffer.getvalue()
		c.close()
		if rcode != 200:
			return None
		else:
			return data
	except:
		return None

def get_remote_rep_rev(rep_serv):
	data = get_url("%sreputation.rev" % rep_serv)
	if data:
		return data.rstrip()
	else:
		return None

def get_remote_patch(rep_serv, revision):
	patch = get_url("%srevisions/reputation.data_%s" % (rep_serv, revision))
	return patch

def get_local_rep_rev(rep_rev):
	f = open(rep_rev, "r")
	data = f.read()
	data = data.rstrip()
	return data

def update_reputation_from_patch(rep_file, rep_rev, patch, remote_rev):
	f = open(rep_file, "r")
	rep_data = f.read()
	f.close()

	rep_data = rep_data.split("\n")
	patch_data = frozenset(patch.split("\n"))

	for i in patch_data:
		try:
			if i != "":
				if i[0] == "-":
					line = list(i) # Delete first char
					line[0] = ""
					line = "".join(line)
					rep_data.remove(line)
				elif i[0] == "+":
					line = list(i) # Delete first char
					line[0] = ""
					line = "".join(line)
					rep_data.append(line)
		except:
			pass

	# Dump new reputation
	f = open(rep_file, "w")
	for ln in rep_data:
		if ln != "":
			f.write("%s\n" % ln)
	f.close()

	# Dump new revision
	f = open(rep_rev, "w")
	f.write(remote_rev)
	f.close()

def download_reputation_database(rep_file, rep_rev, rep_serv):
	try:
		data = get_url("%sreputation.data" % rep_serv)
		if data != None:
			if check_reputation_format(data) == True:
				f = open(rep_file, "w")
				f.write(data)
				f.close()
		data = get_url("%sreputation.rev" % rep_serv)
		if data != None:
			f = open(rep_rev, "w")
			f.write(data)
			f.close()
	except:
		# Error downloading database from server
		logger.info("Error-update: Error downloading database from server")
		pass


if __name__ == '__main__':

    logger.info("Running reputation updater")

    if ((os.path.exists(rep_file) == False) or (os.path.exists(rep_rev) == False)):
        # No reputation file in this box, downloading it.
        logger.info("Downloading reputation database for the first time")
        download_reputation_database(rep_file, rep_rev, rep_serv)
        logger.info("Reputation database downloaded")
        sys.exit() # Done

    # Check for updates
    remote_rev = get_remote_rep_rev(rep_serv)
    local_rev = get_local_rep_rev(rep_rev)

    if remote_rev != local_rev:
        # Updating
        logger.info("Updating database from server")
        patch = get_remote_patch(rep_serv, local_rev)
        if patch != None and remote_rev != None: # Updating your revision
            if check_reputation_format(patch) == True:
                update_reputation_from_patch(rep_file, rep_rev, patch, remote_rev)
        else: # No patch for your revision, downloading the complete database
            download_reputation_database(rep_file, rep_rev, rep_serv)

    logger.info("Reputation updated")
