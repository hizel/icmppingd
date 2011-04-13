OBJS=main.o
HEADERS=sglib.h

CFLAGS=-Wall -O2 -Wno-unused-variable
LDFLAGS+=-liniparser -lev

PROG=icmppingd
CC=clang

all: $(OBJS) $(MOD_OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS) $(MOD_OBJS)

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROG) $(OBJS)

.PHONY: clean
