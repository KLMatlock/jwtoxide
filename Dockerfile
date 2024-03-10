FROM ghcr.io/pyo3/maturin
WORKDIR /build
SHELL ["/bin/bash", "-c"]
COPY . .
RUN maturin build --release
