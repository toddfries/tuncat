PREFIX?=	/usr/local

PROG=	tunbridge
OBJS=	tunbridge.o

CFLAGS=	-g -Wall

all: $(PROG)

install: $(PROG)
	$(INSTALL) $(COPY) -m 0755 $(PROG) $(PREFIX)/bin

tunbridge: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:; -rm -f $(PROG) *.o core *.core *.bak ,* *~ "#"* *.gmon
