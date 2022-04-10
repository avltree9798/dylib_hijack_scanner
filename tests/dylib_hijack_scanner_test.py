import unittest
from modules.dylib_hijack_scanner import DylibHijackScanner


class DylibHijackScannerTest(unittest.TestCase):
	def test_get_all_files(self):
		scanner = DylibHijackScanner(directory_to_scan='tests/fake_storage/Applications', output='')
		expected_returns = [
			'tests/fake_storage/Applications/TestApp2.app/Content/MacOS/TestApp2',
			'tests/fake_storage/Applications/TestApp1.app/Content/MacOS/TestApp1'
		]
		scanner.files_to_scan.sort()
		expected_returns.sort()
		self.assertEqual(scanner.files_to_scan, expected_returns)

	def test_perform_rpath_scanning(self):
		scanner = DylibHijackScanner(directory_to_scan='tests/fake_storage/Applications', output='')
		expected_returns = {
			'tests/fake_storage/Applications/TestApp2.app/Content/MacOS/TestApp2': '@loader_path/../lib/libjli.dylib',
			'tests/fake_storage/Applications/TestApp1.app/Content/MacOS/TestApp1': '@loader_path/../lib/libjli.dylib'
		}
		return_value = scanner._perform_rpath_scanning()
		self.assertEqual(expected_returns, return_value)


if __name__ == '__main__':
	unittest.main()
