#
# File          : Makefile
# Description   : Build file for CMPSC497 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/opt/local/lib
#INCLUDES=-I. -I/opt/local/include
#CC=afl-2.52b/afl-gcc
CC=gcc
CFLAGS=-c $(INCLUDES) -g -Wall -m32 -ffreestanding 
LINK=gcc -g 
LDFLAGS=$(LIBDIRS) -m32 -ffreestanding
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cmpsc497-p1
LIBS=-lcrypto -lm

#
# Project Protections

p1 : $(TARGETS)

cmpsc497-p1 : cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o
	$(LINK) $(LDFLAGS) cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGETS)

tar:
	tar cvfz p3.tgz \
		Makefile \
		cmpsc497-format-*.h \
            cmpsc497-main.c \
	    cmpsc497-kvs.c \
	    cmpsc497-kvs.h \
	    cmpsc497-ssl.c \
	    cmpsc497-ssl.h \
	    cmpsc497-util.c \
	    cmpsc497-util.h 
