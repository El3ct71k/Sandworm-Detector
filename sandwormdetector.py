#!/usr/bin/env python

__author__ = 'El3ct71k'
import os
import re
import zipfile
from shutil import copy, rmtree
from argparse import ArgumentParser
from tempfile import gettempdir

def sandworm_detactor(name):
	if not os.path.exists(name):
		print("File not found")
		exit(-1)
	files = list()
	copy(name, "exploit.zip")
	try:
		with open('exploit.zip', 'rb') as fh:
			z = zipfile.ZipFile(fh)
			for name in z.namelist():
				z.extract(name, gettempdir())
	except zipfile.BadZipfile:
		print("Break file.")
		exit(-1)
	cur_files = '%s/ppt/embeddings/' % gettempdir()
	locations = ['%s/oleObject1.bin' % cur_files, '%s/oleObject2.bin' % cur_files]
	for loc in locations:
		if os.path.exists(loc):
			with open(loc, "rb") as ole:
				mal_file = re.search(r"(?P<host>\\{2}.+([\\/].+)+)", str(ole.read()))
				if mal_file:
					files.append(mal_file.group('host').strip('\x00'))
	os.remove('exploit.zip')
	rmtree("%s/ppt" % gettempdir())
	return files

if __name__ == '__main__':
	parser = ArgumentParser(prog=os.path.basename(__file__))
	parser.add_argument("target", help="Office file to check")
	args = parser.parse_args()
	files = sandworm_detactor(args.target)
	if files:
		print("Sandworm vector attack detacted!\nEvil files:")
		for malware in files:
			print(malware)
	else:
		print("Sandworm vector not found")