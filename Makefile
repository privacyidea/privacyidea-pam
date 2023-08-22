CC = g++
CFLAGS = -g -Wall -fPIC -Iinclude
LDFLAGS = -Wno-undef -lcurl --shared

# Determine which folder to use
libdir.x86_64 = /lib64/security
libdir.i686   = /lib/security

MACHINE := $(shell uname -m)
libdir = $(libdir.$(MACHINE))

target = pam_privacyidea.so
objects = src/pam_privacyidea.o src/PrivacyIDEA.o

$(objects): src/%.o: src/%.cpp

all: pam_privacyidea.so

%.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(target): $(objects)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f src/*.o $(target)

install: all
	strip --strip-unneeded $(target)
	cp $(target) $(libdir)

uninstall:
	rm $(libdir)/$(target)

.PHONY: all clean install uninstall
