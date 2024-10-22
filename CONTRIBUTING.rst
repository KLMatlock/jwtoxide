Contributing
============

Adding Changelog Entries
------------------------

Each new PR should have a change added through `towncrier`. Any PR must have an associated fragment using `towncrier create ...` before it can be merged.

Building Documentation
----------------------

Documentation is built using Sphinx and hosted on Read the Docs.

For building the documentation, you will need a Python environment >=3.12. First install the documentation dependencies:

::
    $ pip install -r docs/requirements.txt

Then build the documentation:

::
    $ make docs