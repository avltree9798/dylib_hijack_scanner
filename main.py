import os
import argparse
import json

from pprint import pprint
from machotools import rewriter_factory
from datetime import datetime


def get_all_files(directory_to_scan: str):
	"""
	Get all files inside a directory and its subdirectories.
	:param directory_to_scan: str
	:return: files to scan
	:rtype: list
	"""
	files_to_scan = []
	for root, _, files in os.walk(directory_to_scan):
		for file in files:
			files_to_scan.append(os.path.join(root, file))

	return files_to_scan

def get_rpaths_and_libraries(file: str):
	"""
	Get the RPATHs and libraries for a given file.
	:param file: str
	:return: rpaths and libraries for the file
	:rtype: dict
	"""
	try:
		rewriter = rewriter_factory(file)
		rpaths = rewriter.rpaths
		if len(rpaths) == 0:
			return {}

		libraries = []
		for dependency in rewriter.dependencies:
			if dependency.startswith('@rpath'):
				libraries.append(dependency[6:])

		if len(libraries) > 0:
			return {
				'rpaths': rewriter.rpaths,
				'libraries': libraries
			}
	except:
		return {}


def perform_scanning(scan_items: dict):
	"""
	Perform a scanning to determine whether DYLIB Hijacking are possible.
	:param scan_items: dict
	:return: Vulnerable binary with its library.
	:rtype: dict
	"""
	vulnerable_libraries = {}
	for file, entry in scan_items.items():
		executable_path = '/'.join(file.split(os.sep)[:-1])
		for library in entry.get('libraries'):
			for rpath in entry.get('rpaths'):
				original_rpath = rpath
				if '@loader_path' not in rpath:
					continue
				rpath = rpath.replace('@loader_path', '')
				dylib_to_check = f"{executable_path}{rpath}{library}"
				if not os.path.isfile(dylib_to_check):
					vulnerable_libraries[file] = f"{original_rpath}{library}"
					continue

	return vulnerable_libraries

def main(directory_to_scan: str, output: str):
	assert os.path.isdir(directory_to_scan)

	started_at = str(datetime.now())
	print(f"Gathering all files at: {directory_to_scan}")
	files_to_scan = get_all_files(directory_to_scan)
	print(f"Found {len(files_to_scan)} files, performing analysis...")
	scan_items = {}
	for file in files_to_scan:
		scan_item = get_rpaths_and_libraries(file)
		if scan_item:
			scan_items[file] = scan_item

	vulnerable_libraries = perform_scanning(scan_items)
	ended_at = str(datetime.now())
	if vulnerable_libraries:
		print("These are the vulnerable binaries")
		pprint(vulnerable_libraries)
		if output:
			with open(output, 'w+') as f:
				output_dictionary = {
					'scan_info': {
						'directory_to_scan': directory_to_scan,
						'started_at': started_at,
						'ended_at': ended_at
					},
					'scan_results':vulnerable_libraries
				}
				f.write(json.dumps(output_dictionary, indent=4))
				f.close()
	else:
		print("No vulnerable binary was found")


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"--dir",
		help="Set a directory to scan.",
		type=str,
		default='/Applications/'
	)

	parser.add_argument(
		"--output",
		help="Set the output file.",
		type=str,
		default=''
	)

	args = parser.parse_args()
	main(args.dir, args.output)
