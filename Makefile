CPPFLAGS ?= $(shell pkg-config --cflags wireshark)
CFLAGS ?= -fPIC
LIBDIR ?= $(HOME)/.local/lib
WIRESHARK_PLUGINDIR ?= $(shell pkg-config "--define-variable=libdir=$(LIBDIR)" --variable=plugindir wireshark)

ifeq ($(OS),Windows_NT)
.DEFAULT_GOAL := packet-minecraft.dll
else
.DEFAULT_GOAL := packet-minecraft.so
endif

generated.c: generate.js
	node generate.js > $@

packet-minecraft.o: packet-minecraft.c generated.c

packet-minecraft.dll packet-minecraft.so: packet-minecraft.o
	$(LINK.o) $^ -shared $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: install-unix
install-unix: packet-minecraft.so
	mkdir -p $(WIRESHARK_PLUGINDIR)/epan
	cp -p packet-minecraft.so $(WIRESHARK_PLUGINDIR)/epan/minecraft.so

.PHONY: install
ifeq ($(OS),Windows_NT)
install:
else
install: install-unix
endif

.PHONY: clean
clean:
	$(RM) generated.c packet-minecraft.o packet-minecraft.so packet-minecraft.dll
