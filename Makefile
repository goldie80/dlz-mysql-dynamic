prefix = /usr
libdir = $(prefix)/lib/bind9

CFLAGS=-fPIC -g
BDB_LIBS=-ldb

all: dlz_mysql_dynamic.so

dlz_mysql_dynamic.so:
	$(CC) $(CFLAGS) -shared -o dlz_mysql_dynamic.so dlz_mysql_dynamic.c $(BDB_LIBS)

clean:
	rm -f dlz_mysql_dynamic.so

install: dlz_mysql_dynamic.so
	mkdir -p $(DESTDIR)$(libdir)
	install dlz_mysql_dynamic.so $(DESTDIR)$(libdir)
