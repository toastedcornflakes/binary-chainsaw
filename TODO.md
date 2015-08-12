* Make a basic REPL to interact with the disassembly (see http://docs.python.org/3.3/library/code.html)

* `Document`: implement symbols to name procedures / code blocks
* Rewrite SparseBytes and API to use variable length page, instead of the "undefined" meta data
* `API.py`: Make a `write_bytes` interface that copy a whole slice
* Make the disassembler disassemble a slice without copying data
* Add an "executable strings" operation (That doesn't do any parsing)
* ELF loader: parse the sections to gain more code address
	parse .dynsym to avoid disassembling crap
* Implement generic, pluggable disassembly heuristics for detecting code. Make an example using `__libc_start_main`
* Write a pluggable analyzer interface, like the loader 
