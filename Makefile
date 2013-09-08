CFLAGS=-O2
BINDIR=/usr/local/sbin

noxref: noxref.c
	$(CC) -pthread -o $@ -W $(CFLAGS) $<

clean:
	$(RM) noxref

install: noxref
	strip --strip-all $<
	install -D $+ $(BINDIR)
	-kill $(shell pidof noxref)
