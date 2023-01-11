
COMMIT_HASH=$(shell git rev-parse --short=8 HEAD 2>/dev/null)
BUILD_TIME=$(shell date +%FT%T%z)

COMMIT=$(shell git rev-parse HEAD 2>/dev/null)

VERSION_TAG = $(shell git describe --tags --exact-match 2>/dev/null | cut -f 1 -d '-' 2>/dev/null)

# If no git tag is set, fallback to 'DEVELOPMENT'
ifeq ($(strip ${VERSION_TAG}),)
VERSION_TAG := Development
endif

CC ?= cc
CFLAGS ?= -O -Wall -D_FORTIFY_SOURCE=2 -Wextra -Wformat-security 
CFLAGS += -DENABLE_CRYPTO=yes -DBUILD_TIME=$(BUILD_TIME) -DVERSION=$(VERSION_TAG) -DCOMMIT_HASH=$(COMMIT_HASH) -I/usr/include/openvpn -I/usr/include/openssl -O3 -fmessage-length=0 -fPIC
LDFLAGS += -shared

SRC 	= $(wildcard *.c)
OUT	= $(SRC:%.c=%.so)

%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o "liblog-cert-expire-times.so.$(VERSION_TAG)" $<

all: clean plugin

plugin: $(OUT)

clean:
	rm -f *.so* *.d *.o 

