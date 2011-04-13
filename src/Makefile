OBJS=main.o
HEADERS=

CFLAGS=-Wall -O2
LDFLAGS+=-liniparser

PROG=icmppingd
CC=clang

all: $(OBJS) $(MOD_OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS) $(MOD_OBJS)

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROG) $(OBJS)

.PHONY: clean
