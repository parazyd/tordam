# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

BIN =\
	damhs.py \
	damauth.py

all:
	@echo 'Run "make install" to install the scripts to $(DESTDIR)$(PREFIX)/bin'

install:
	@echo 'Installing scripts to $(DESTDIR)$(PREFIX)/bin'
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
	for f in $(BIN); do chmod 755 "$(DESTDIR)$(PREFIX)/bin/$$f"; done

uninstall:
	@echo 'Uninstalling scripts from $(DESTDIR)$(PREFIX)/bin'
	for f in $(BIN); do rm -f "$(DESTDIR)$(PREFIX)/bin/$$f"; done

.PHONY: all install uninstall
