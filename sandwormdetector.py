#!/usr/bin/env python

__author__ = 'El3ct71k'
import os
import re
import zipfile
from argparse import ArgumentParser

def sandworm_detactor(name):
	if not os.path.exists(name):
		print("File not found")
		exit(-1)
	files = list()

	try:
		with zipfile.ZipFile(name, 'r') as z:
			for f in ('ppt/embeddings/oleObject1.bin', 'ppt/embeddings/oleObject2.bin'):
				mal_file = re.search(r"(?P<host>\\{2}.+([\\/].+)+)", z.read(f))
				if mal_file:
					files.append(mal_file.group('host'))
	except zipfile.BadZipfile:
		print("Not a .ppsx file.")
	except KeyError:
		print("Sandworm vector not found")
	finally:
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
