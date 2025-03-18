CC = gcc
CFLAGS = -m32 -g -O0

TARGET = otcc

all: $(TARGET)

$(TARGET): ./rewrite/otcc_rewrite.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean