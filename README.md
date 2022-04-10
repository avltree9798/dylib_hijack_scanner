# dylib_hijack_scanner

This script will helps you to automatically check a potential dynamic library hijack attack in a given directory.

## Installation Guide
```
$ pip install -r requirements.txt
```

## Usage
```
╰─(.venv) ⠠⠵ python main.py --help
usage: main.py [-h] [--dir DIR] [--output OUTPUT]

optional arguments:
  -h, --help       show this help message and exit
  --dir DIR        Set a directory to scan. (default '/Applications/')
  --output OUTPUT  Set the output file for scan report.
```

## How to contribute
- Install the required tools for development
  ```
  $ pip install -r requirements.txt 
  $ pip install -r requirements-dev.txt
  ```
- Develop your feature with its test cases
- Run `make test` before making a pull request, make sure everything is passed
- Push the code into your own branch and make a pull request =)
