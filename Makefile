CFLAGS = -g -O2 -Wall -std=gnu99
OBJECTS = main.o
TARGET = csg

all: $(TARGET)

$(TARGET):$(OBJECTS)
	$(CC) -o $@ $^ -lip4tc
	$(RM) $(OBJECTS)
