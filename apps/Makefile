ARCH ?= X86_64

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
RM=$(CROSS_COMPILE)rm
DEBUG_LEVEL ?= 2
SHARED ?= 0
VERSION ?= 0

ROOT_DIRECTORY=$(PWD)/..
BIN=test_http_over_tls_client test_http_over_tls_server test_http_over_dtls_client test_http_over_dtls_server

CLIENT_SRC=test_http_over_tls_client.c test_http_over_dtls_client.c
CLIENT_OBJ=$(CLIENT_SRC:.c=.o)
SERVER_SRC=test_http_over_tls_server.c test_http_over_dtls_server.c
SERVER_OBJ=$(SERVER_SRC:.c=.o)

ifeq ($(VERSION), 0)
	CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/fastpqdelivery/include -DDEBUG_LEVEL=$(DEBUG_LEVEL)
	LDFLAGS=-L$(ROOT_DIRECTORY)/fastpqdelivery/lib64 -lssl -lcrypto -lsimple_http -L. -lpthread
else ifeq ($(VERSION), 1)
	CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/openssl-3.3.0-lib/include -DDEBUG_LEVEL=$(DEBUG_LEVEL)
	LDFLAGS=-L$(ROOT_DIRECTORY)/openssl-3.3.0-lib/lib64 -lssl -lcrypto -lsimple_http -L. -lpthread
else
	CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/openssl-1.1.1f-lib/include -DDEBUG_LEVEL=$(DEBUG_LEVEL)
	LDFLAGS=-L$(ROOT_DIRECTORY)/openssl-1.1.1f-lib/lib64 -lssl -lcrypto -lsimple_http -L. -lpthread
endif

all: test_http_over_tls_client test_http_over_tls_server test_http_over_dtls_client test_http_over_dtls_server

test_http_over_tls_client: $(CLIENT_OBJ)
	$(CC) -o $@ test_http_over_tls_client.o $(LDFLAGS)
	@echo "LINK => $@"

test_http_over_tls_server: $(SERVER_OBJ)
	$(CC) -o $@ test_http_over_tls_server.o $(LDFLAGS)
	@echo "LINK => $@"

test_http_over_dtls_client: $(CLIENT_OBJ)
	$(CC) -o $@ test_http_over_dtls_client.o $(LDFLAGS)
	@echo "LINK => $@"

test_http_over_dtls_server: $(SERVER_OBJ)
	$(CC) -o $@ test_http_over_dtls_server.o $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
	@echo "CC <= $<"

clean:
	$(RM) $(BIN) $(CLIENT_OBJ) $(SERVER_OBJ)
