#
# libaes -- Copyright Quentin Carbonneaux 2009
#

LIBAES = libaes.a
LIBAES_OBJ = aes.o
LIBAES_SRC = aes.c aes.h tables.h
CHECK_OBJ = libaestest_main.o
# Remove this comment to compile with debugging symbols.
CDEBUG = #-g
CFLAGS = $(CDEBUG) -Wall -I. -O3

.PHONY: all

all: $(LIBAES)

$(LIBAES): $(LIBAES_OBJ)
	ar rvs $@ $^

$(LIBAES_OBJ): $(LIBAES_SRC)

.PHONY: check clean

check: $(CHECK_OBJ) $(LIBAES)
	$(CC) $^ -L. -laes -o libaestest
	@if ./libaestest | diff - libaestest.out > /dev/null; then \
		echo -ne "\n\n* libaes is OK.\n"; \
	else \
		echo -ne "\n\n!! Invalid results, recompile or download again the archive.\n" ;\
		false;\
	fi

clean:
	-$(RM) $(LIBAES_OBJ) $(LIBAES) libaestest $(CHECK_OBJ)