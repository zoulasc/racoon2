
RC_LIBDIR= ..
CFLAGS= -g -I..
LIBS= $(RC_LIBDIR)/libracoon.a
PROGS= test_addrlist test_plog

all: $(PROGS)
	
test_addrlist: test_addrlist.c $(LIBS)
	cc $(CFLAGS) -o $@ $< $(LIBS)

test_plog: test_plog.c $(LIBS)
	cc $(CFLAGS) -o $@ $< $(LIBS)

$(RC_LIBDIR)/libracoon.a:
	(cd $(RC_LIBDIR) && make libracoon.a)

clean:
	rm -f *.o $(PROGS)
