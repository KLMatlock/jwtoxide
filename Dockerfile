FROM ghcr.io/pyo3/maturin
WORKDIR /build
SHELL ["/bin/bash", "-c"]
COPY . .
CMD ["build", "--release"]
