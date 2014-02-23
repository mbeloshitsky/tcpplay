TARGET:=tcpplay
INSTALLPATH:=/usr/local/bin

all: $(TARGET)

$(TARGET): tcpplay.c
	$(CC) tcpplay.c -o $(TARGET) -lpcap

install: $(TARGET)
	cp $(TARGET) $(INSTALLPATH) 

clean:
	rm $(TARGET)
