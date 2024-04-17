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
