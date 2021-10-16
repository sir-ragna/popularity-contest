
CC = clang
CFLAGS = -Wall
TARGET = main

all: $(TARGET)

debug: $(TARGET).c
	$(CC) -g -Wall -o $(TARGET) $(TARGET).c

perf: $(TARGET).c
	$(CC) -pg -g -Wall -o $(TARGET) $(TARGET).c

release: $(TARGET).c
	$(CC) -O3 -Wall -o $(TARGET) $(TARGET).c

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) main
