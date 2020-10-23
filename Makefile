CPPFLAGS := $(shell pkg-config --cflags wireshark)
CFLAGS ?= -fPIC

generated.c:
	node generate.js > $@

packet-minecraft.o: packet-minecraft.c generated.c

packet-minecraft.so: packet-minecraft.o
	$(LINK.o) $^ -shared $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: install
install: packet-minecraft.so
	mkdir -p $(HOME)/.local/lib/wireshark/plugins/3.2/epan
	cp -p packet-minecraft.so $(HOME)/.local/lib/wireshark/plugins/3.2/epan/packet-minecraft.so
