#
# Copyright Quentin Carbonneaux 2009
# Time-stamp: <2009-12-30 12:40:24>
#

.PHONY: all install clean

all:
	cd libaes && make
	cd aescrypt && make

clean:
	cd libaes && make clean
	cd aescrypt && make clean

install: all
	cd aescrypt && make install