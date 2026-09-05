build:
	SOURCE_DATE_EPOCH=$(shell git log -1 --pretty=%ct) uv build --no-sources

clean:
	rm -rf dist/

clean.all: clean
	find .  -type d -name .mypy_cache -o -name __pycache__ -exec rm -rf "{}" \+
