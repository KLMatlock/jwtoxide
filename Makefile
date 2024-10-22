PYTHON := python3

install-dev:
	maturin develop --extras test,docs,lint,changelog

test:
	$(PYTHON) -m pytest

format:
	cargo fmt
	ruff format .

lint:
	cargo clippy
	ruff check .

build:
	maturin build --release

get-release:
	grep NEWS.rst -P "^Pyauditlogger\s+\d+\.\d+\.\d+\s+\(\d{4}-\d{2}-\d{2}\)\n=+" | tail -n +2

.PHONY: docs
docs:
	cd docs && make html
