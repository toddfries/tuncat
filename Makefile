PREFIX?=	/usr/local

PROG=	tuncat
OBJS=	tuncat.o

CFLAGS=	-g -Wall

all: $(PROG)

install: $(PROG)
	$(INSTALL) $(COPY) -m 0755 $(PROG) $(PREFIX)/bin

tuncat: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:; -rm -f $(PROG) *.o core *.core *.bak ,* *~ "#"* *.gmon
