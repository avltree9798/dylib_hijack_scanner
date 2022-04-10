import os
import json

from pprint import pprint
from datetime import datetime
from machotools import rewriter_factory


class DylibHijackScanner(object):
	def __init__(self, directory_to_scan: str, output: str):
		self.directory_to_scan = directory_to_scan
		self.output = output
		self.files_to_scan = self._get_all_files()
		self.scan_items = {}

	def _get_all_files(self):
		"""
		Get all files inside a directory and its subdirectories.
		:param self: DylibHijackScanner
		:return: files to scan
		:rtype: list
		"""
		files_to_scan = []
		for root, _, files in os.walk(self.directory_to_scan):
			for file in files:
				files_to_scan.append(os.path.join(root, file))

		return files_to_scan

	def _get_rpaths_and_libraries(self, file: str):
		"""
		Get the RPATHs and libraries for a given file.
		:param self: DylibHijackScanner
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
		except Exception:
			return {}

	def _perform_scanning(self):
		"""
		Perform a scanning to determine whether DYLIB Hijacking are possible.
		:param self: DylibHijackScanner
		:return: Vulnerable binary with its library.
		:rtype: dict
		"""
		vulnerable_libraries = {}
		for file, entry in self.scan_items.items():
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

	def scan(self):
		assert os.path.isdir(self.directory_to_scan)
		for file in self.files_to_scan:
			scan_item = self._get_rpaths_and_libraries(file)
			if scan_item:
				self.scan_items[file] = scan_item

		started_at = str(datetime.now())
		print(f"Gathering all files at: {self.directory_to_scan}")
		print(f"Found {len(self.files_to_scan)} files, performing analysis...")
		vulnerable_libraries = self._perform_scanning()
		ended_at = str(datetime.now())
		if vulnerable_libraries:
			print("These are the vulnerable binaries")
			pprint(vulnerable_libraries)
			if self.output:
				with open(self.output, 'w+') as f:
					output_dictionary = {
						'scan_info': {
							'directory_to_scan': self.directory_to_scan,
							'started_at': started_at,
							'ended_at': ended_at
						},
						'scan_results': vulnerable_libraries
					}
					f.write(json.dumps(output_dictionary, indent=4))
					f.close()
		else:
			print("No vulnerable binary was found")
