.DELETE_ON_ERROR:

all:
	echo >&2 "Must specify target."

test:
	tox

venv:
	tox -evenv

clean:
	rm -rf build/ dist/ .tox
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

.PHONY: all test venv clean install-hooks