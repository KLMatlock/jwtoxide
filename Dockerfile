FROM python:3.9-bullseye
WORKDIR /build
SHELL ["/bin/bash", "-c"]
COPY . .
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y && \
    source "$HOME/.cargo/env" && \
    pip install maturin && \
    python3 -m venv .venv && \
    source .venv/bin/activate && \
    maturin develop
