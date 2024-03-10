PYTHON := python3

install-dev:
	maturin develop --extras test,docs,lint

test:
	$(PYTHON) -m pytest

format:
	cargo fmt
	ruff format .

lint:
	cargo clippy
	ruff lint .

build:
	maturin build --release
