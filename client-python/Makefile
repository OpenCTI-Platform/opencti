build:
	SOURCE_DATE_EPOCH=$(shell git log -1 --pretty=%ct) python3 -m build

clean:
	rm -rf *.egg-info/ build/ dist/

clean.all: clean
	find .  -type d -name .mypy_cache -o -name __pycache__ -exec rm -rf "{}" \+
