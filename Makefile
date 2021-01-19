CPPFLAGS := $(shell pkg-config --cflags wireshark)
CFLAGS ?= -fPIC
LIBDIR := $(HOME)/.local/lib
WIRESHARK_PLUGINDIR := $(shell pkg-config "--define-variable=libdir=$(LIBDIR)" --variable=plugindir wireshark)

.DEFAULT_GOAL := packet-minecraft.so

generated.c:
	node generate.js > $@

packet-minecraft.o: packet-minecraft.c generated.c

packet-minecraft.so: packet-minecraft.o
	$(LINK.o) $^ -shared $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: install
install: packet-minecraft.so
	mkdir -p $(WIRESHARK_PLUGINDIR)/epan
	cp -p packet-minecraft.so $(WIRESHARK_PLUGINDIR)/epan/minecraft.so

.PHONY: clean
clean:
	$(RM) -rf generated.c packet-minecraft.o packet-minecraft.so
