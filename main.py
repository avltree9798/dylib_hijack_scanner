import argparse
from modules.dylib_hijack_scanner import DylibHijackScanner


def main(directory_to_scan: str, output: str):
	dylib_hijack_scanner = DylibHijackScanner(directory_to_scan=directory_to_scan, output=output)
	dylib_hijack_scanner.scan()


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
