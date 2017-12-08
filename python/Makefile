# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

BIN =\
	decodehs.py \
	dirauth.py

all:
	@echo 'Run "make install" to install the scripts to $(DESTDIR)$(PREFIX)/bin'

install:
	@echo 'Installing scripts to $(DESTDIR)$(PREFIX)/bin'
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
