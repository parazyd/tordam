# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

SRC =\
	redis.conf \
	torrc

all:
	@echo 'Run "make install" to install to $(DESTDIR)$(PREFIX)/share/tor-dam'

install:
	@echo 'Installing to $(DESTDIR)$(PREFIX)/share/tor-dam'
	mkdir -p $(DESTDIR)$(PREFIX)/share/tor-dam
	cp -f $(SRC) $(DESTDIR)$(PREFIX)/share/tor-dam

uninstall:
	@echo 'Uninstalling from $(DESTDIR)$(PREFIX)/share/tor-dam'
	rm -rf $(DESTDIR)$(PREFIX)/share/tor-dam

.PHONY: all install uninstall
