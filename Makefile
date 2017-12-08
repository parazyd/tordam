# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

all:
	@echo 'Run "make install" to install into $(DESTDIR)$(PREFIX)'

install:
	@make -C python install

uninstall:
	@make -C python uninstall

.PHONY: all install uninstall
