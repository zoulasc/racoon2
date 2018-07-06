all: build

build: build-recursive

build-recursive: .MAKE
	@for d in $(SUBDIR) ; do \
		if test -d $$d ; then \
			echo "===> Change directory to $$d" ; \
			(cd $$d && $(MAKE)) || exit 1 ; \
		fi ; done

install: install-recursive

install-recursive: .MAKE
	@for d in $(SUBDIR) ; do \
		if test -d $$d ; then \
			echo "===> Change directory to $$d" ; \
			(cd $$d && $(MAKE) install) || exit 1 ; \
		fi ; done

# pmake does not require '-' before MAKEFLAGS but gmake does.
# Recent makes automatically pass command line options to submakes via
# environment variables, so we actually don't need MFLAGS nor MAKEFLAGS here.

clean: clean-recursive

clean-recursive: .MAKE
	-@for d in $(ALLSUBDIR) ; do \
		if test -d $$d; then \
			echo "===> Change directory to $$d" ; \
			(cd $$d && $(MAKE) clean) \
		fi ; done

distclean: distclean-recursive distclean-here

distclean-recursive: .MAKE
	-@for d in $(ALLSUBDIR) ; do \
		if test -d $$d; then \
			echo "===> Change directory to $$d" ; \
			(cd $$d && $(MAKE) distclean) \
		fi ; done

depend: depend-recursive

depend-recursive: .MAKE
	for d in $(SUBDIR) ; do \
		if test -d $$d; then \
			echo "===> Change directory to $$d" ; \
			(cd $$d && $(MAKE) depend) || exit 1 ; \
		fi ; done

# dummy target for gmake.  gmake magically works recursively with -n.
.MAKE:
