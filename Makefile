# See LICENSE file for copyright and license details.

PREFIX ?= /usr/local

all:
	@echo 'Run "make install" to install into $(DESTDIR)$(PREFIX)'

install:
	@make -C python install
	@make -C contrib install

uninstall:
	@make -C python uninstall
	@make -C contrib uninstall

.PHONY: all install uninstall
