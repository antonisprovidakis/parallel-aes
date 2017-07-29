#
# aescrypt -- Copyright Quentin Carbonneaux 2009
#

BIN = aescrypt
BIN_SRC = aescrypt.c
BIN_OBJ = aescrypt.o
libaesdir = ../libaes/
# Remove this comment to compile with debugging symbols.
CDEBUG = #-g
CFLAGS = $(CDEBUG) -Wall -I$(libaesdir) -O2
LDFLAGS = -g -laes -L$(libaesdir)
INSTALL = install -c

prefix = /usr
bindir = $(prefix)/bin

.PHONY: all
all: $(BIN)

$(BIN_OBJ): $(BIN_SRC)

$(BIN): $(BIN_OBJ)
	$(CC) $(CFLAGS) $(BIN_OBJ) $(LDFLAGS) -o $@

.PHONY: install
install: all
	$(INSTALL) $(BIN) $(bindir)/$(BIN)

.PHONY: clean
clean:
	-$(RM) $(BIN_OBJ) $(BIN)