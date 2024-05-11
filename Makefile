KERNEL_UAPI_PATH = ./linux/usr/include/

CFLAGS += -I${KERNEL_UAPI_PATH} -O2 -pipe -std=gnu11
LDFLAGS += -Wl,--as-needed -Wl,-O1

test: test.c
	${CC} ${CFLAGS} -o$@ $< ${LDFLAGS}
