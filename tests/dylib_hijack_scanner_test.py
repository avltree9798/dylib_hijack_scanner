import unittest
import os
from unittest.mock import patch
from modules.dylib_hijack_scanner import DylibHijackScanner

OS_WALK_RETURN = [
	('/foo', ('bar',), ('baz',)),
	('/foo/bar', (), ('spam', 'eggs')),
]


class DylibHijackScannerTest(unittest.TestCase):
	@patch.object(os, 'walk')
	def test_get_all_files(self, walk):
		walk.return_value = OS_WALK_RETURN
		scanner = DylibHijackScanner(directory_to_scan='/Applications/', output='')
		self.assertEqual(scanner.files_to_scan, ['/foo/baz', '/foo/bar/spam', '/foo/bar/eggs'])


if __name__ == '__main__':
	unittest.main()
