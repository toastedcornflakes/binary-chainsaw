A small, WIP, extensible [capstone](http://capstone-engine.org)-based disassembler.

Writing loaders
--------------

start by importing the API

	import API

The loader should consist of two function:

* `accept_file(file)` returns if the loader can parse the file
* `load_file(file, doc)` loads the file into the document provided using `writeByte()`, `push_proc()`, `processor_type`.

For an example, see [`loaders/ELF.py`](loaders/ELF.py)

Requirements
------------

* [capstone](http://capstone-engine.org) python3 bindings


Todo
----

* disassembler logic needs to be able to stop earlier
* usable interface to read the disassembly and follow the references
* `Document`: implement symbols to name procedures / code blocks
* Cleaner SparseBytes API
* ELF loader: parse the sections to gain more code address
	parse .dynsym to avoid disassembling crap
* Generic, plugin-able disassembly and analyzer heuristics. Example using `__libc_start_main` ?
* Other architecture (RISC would be easier)
