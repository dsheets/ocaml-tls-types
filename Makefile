.PHONY: build install uninstall reinstall clean

FINDLIB_NAME=tls-types
BUILD=_build/lib
SRC=lib
FLAGS=-package ctypes
EXTRA_META=requires = \"ctypes\"

build:
	ocamlbuild -use-ocamlfind -I $(SRC) $(FLAGS) tls_types.cma
	ocamlbuild -use-ocamlfind -I $(SRC) $(FLAGS) tls_types.cmxa

META: META.in
	cp META.in META
	echo $(EXTRA_META) >> META

install: META
	ocamlfind install $(FINDLIB_NAME) META \
		$(SRC)/tls_types.ml \
		$(BUILD)/tls_types.cmi \
		$(BUILD)/tls_types.cma \
		$(BUILD)/tls_types.cmxa

uninstall:
	ocamlfind remove $(FINDLIB_NAME)

reinstall: uninstall install

clean:
	ocamlbuild -clean
	rm -f META
