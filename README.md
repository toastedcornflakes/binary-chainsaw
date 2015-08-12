A small, WIP, extensible [capstone](http://capstone-engine.org)-based disassembler.

Writing loaders
--------------

For an example, see `loaders/ELF.py`

start by importing the API

	import API

The loader should consist of two function:

* `accept_file(file)` returns if the loader can parse the file
* `load_file(file, doc)` loads the file into the document provided using `writeByte()`, `push_proc()`, `processor_type`.


Requirements
------------

	* [capstone](http://capstone-engine.org) python3 bindings
