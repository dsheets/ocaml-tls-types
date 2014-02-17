.PHONY: build install uninstall reinstall clean

FINDLIB_NAME=tls-types
BUILD=_build/lib
SRC=lib
FLAGS=-package ctypes
EXTRA_META=requires = \"ctypes\"

build:
	mkdir -p $(BUILD)
	ocamlfind ocamlc -o $(BUILD)/tls_types.cmi -I $(BUILD) -I $(SRC) \
		$(FLAGS) -c $(SRC)/tls_types.mli
	ocamlfind ocamlmklib -o $(BUILD)/tls_types -I $(BUILD) \
		$(FLAGS) $(SRC)/tls_types.mli

META: META.in
	cp META.in META
	echo $(EXTRA_META) >> META

install: META
	ocamlfind install $(FINDLIB_NAME) META \
		$(SRC)/tls_types.mli \
		$(BUILD)/tls_types.cmi \
		$(BUILD)/tls_types.cma \
		$(BUILD)/tls_types.cmxa

uninstall:
	ocamlfind remove $(FINDLIB_NAME)

reinstall: uninstall install

clean:
	rm -rf _build
	bash -c "rm -f META lib/{tls_types}.cm?"
