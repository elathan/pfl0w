GAS=as
LD=ld
CC=gcc
CFLAGS=-Wall `pkg-config glib-2.0 --cflags`  
LDFLAGS=-lpcap `pkg-config glib-2.0 --libs`   

all: pfl0w 

pfl0w: pfl0w.c
	$(CC) $(CFLAGS) pfl0w.c -lpcap -o pfl0w
	sudo setcap cap_net_raw=ep ./pfl0w

clean:
	rm pfl0w	
	
