jwtoxide
========

PyO3 bindings to the `jsonwebtoken` library in Rust.

This library provides Python bindings to the jsonwebtoken_ Rust library. The JSON Web Token (JWT)
has become the de-facto standard for API authentication on the web. 

This is a pure Rust implementation and requires no other dependencies to use.

Installation
------------

Installation can be done through pypi using pip:

::
    
    $ pip install jwtoxide

Development
-----------

Building for development requires `maturin`. Once installed run `make install-dev`.

.. _jsonwebtoken: https://docs.rs/jsonwebtoken/latest/jsonwebtoken/
