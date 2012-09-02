prefix = /usr
libdir = $(prefix)/lib/bind9

CFLAGS=-fPIC -g
MYSQL_LIBS=-lmysqlclient

# Bind 9.8
dlz_dlopen_version=1
# Bind 9.9
#dlz_dlopen_version=2

all: sdlz_helper.o dlz_mysql_dynamic.o dlz_mysql_dynamic.so

sdlz_helper.o:
	$(CC) $(CFLAGS) -I include/ -DUSE_DLZ_DLOPEN_V$(dlz_dlopen_version) -c sdlz_helper.c -o sdlz_helper.o

dlz_mysql_dynamic.o:
	$(CC) $(CFLAGS) -DUSE_DLZ_DLOPEN_V$(dlz_dlopen_version) -o dlz_mysql_dynamic.o -c dlz_mysql_dynamic.c 

dlz_mysql_dynamic.so:
	$(CC) $(CFLAGS) -shared -o dlz_mysql_dynamic.so sdlz_helper.o dlz_mysql_dynamic.o

clean:
	rm -f sdlz_helper.o dlz_mysql_dynamic.so

install: dlz_mysql_dynamic.so
	mkdir -p $(DESTDIR)$(libdir)
	install dlz_mysql_dynamic.so $(DESTDIR)$(libdir)
