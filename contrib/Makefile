# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

SRC =\
	redis.conf \
	torrc

all:
	@echo 'Run "make install" to install to $(DESTDIR)$(PREFIX)/share/tor-dam'
	@echo 'Run "make install-init" to install initscripts to $(DESTDIR)/etc'

install:
	@echo 'Installing to $(DESTDIR)$(PREFIX)/share/tor-dam'
	mkdir -p $(DESTDIR)$(PREFIX)/share/tor-dam
	cp -f $(SRC) $(DESTDIR)$(PREFIX)/share/tor-dam

install-init:
	@echo 'Installing to $(DESTDIR)/etc/init.d and $(DESTDIR)/etc/conf.d'
	mkdir -p $(DESTDIR)/etc/init.d $(DESTDIR)/etc/conf.d
	cp -f dam-dir.init $(DESTDIR)/etc/init.d/dam-dir
	cp -f dam-client.init $(DESTDIR)/etc/init.d/dam-client
	chmod 755 $(DESTDIR)/etc/init.d/dam-dir
	chmod 755 $(DESTDIR)/etc/init.d/dam-client
	cp -f dam-dir.conf $(DESTDIR)/etc/conf.d/dam-dir
	cp -f dam-client.conf $(DESTDIR)/etc/conf.d/dam-client

uninstall:
	@echo 'Uninstalling from $(DESTDIR)$(PREFIX)/share/tor-dam'
	rm -rf $(DESTDIR)$(PREFIX)/share/tor-dam
	@echo 'Uninstalling initscripts from $(DESTDIR)/etc'
	rm -f $(DESTDIR)/etc/init.d/dam-dir $(DESTDIR)/etc/init.d/dam-client
	rm -f $(DESTDIR)/etc/conf.d/dam-dir $(DESTDIR)/etc/conf.d/dam-client

.PHONY: all install install-init uninstall
