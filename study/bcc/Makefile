CC=clang

TARGET=hello

LIBS=-lbcc -lbpf

all: $(TARGET)

$(TARGET):
	$(CC) $(LIBS) $@.c -o $@

clean:
	rm -r $(TARGET)