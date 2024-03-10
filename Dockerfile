FROM python:3.9-bullseye
WORKDIR /build

COPY . .
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . "$HOME/.cargo/env" && \
    pip install maturin && \
    python3 -m venv .venv && \
    . .venv/bin/activate && \
    maturin develop
