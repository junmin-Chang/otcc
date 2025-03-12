CC = gcc
CFLAGS = -m32 -g -O0

TARGET = otcc

all: $(TARGET)

$(TARGET): otccelfn.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean