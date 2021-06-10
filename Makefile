# Use gmake on Solaris

VERSION = "1.0.0"
PREFIX ?= /usr
BINDIR ?= sbin
MANDIR ?= share/man/man8

OS := $(shell uname -s)
MACH ?= 64

INSTALL_SunOS = ginstall
INSTALL_Linux = install

INSTALL ?= $(INSTALL_$(OS))

# If CC is set to 'cc', *_cc flags (Sun studio compiler) will be used.
# If set to 'gcc', the corresponding GNU C flags (*_gcc) will be used.
# For all others one needs to add corresponding rules.
CC ?= gcc
OPTIMZE_cc ?= -xO3
OPTIMZE_gcc ?= -O3
OPTIMZE ?= $(OPTIMZE_$(CC)) -DNDEBUG

CFLAGS_cc = -xcode=pic32
CFLAGS_cc += -errtags -erroff=%none,E_UNRECOGNIZED_PRAGMA_IGNORED,E_ATTRIBUTE_UNKNOWN,E_NONPORTABLE_BIT_FIELD_TYPE -errwarn=%all
CFLAGS_cc += -pedantic -v
CFLAGS_gcc = -fPIC -fsigned-char -pipe -Wno-unknown-pragmas -Wno-unused-result
CFLAGS_gcc += -fdiagnostics-show-option -Wall -Werror
CFLAGS_gcc += -pedantic -Wpointer-arith -Wwrite-strings -Wstrict-prototypes -Wnested-externs -Winline -Wextra -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wundef -Wunused -Wno-variadic-macros -Wno-parentheses -Wcast-align -Wcast-qual
CFLAGS_gcc += -Wno-unused-function -Wno-multistatement-macros

CFLAGS_Linux =
CFLAGS_SunOS = -I/usr/include/microhttpd -D_MHD_DEPR_MACRO
CFLAGS_libprom ?= $(shell [ -d /usr/include/libprom ] && printf -- '-I/usr/include/libprom' || printf -- '-I../libprom/prom/include' )
CFLAGS ?= -m$(MACH) $(CFLAGS_$(CC)) $(CFLAGS_libprom) $(OPTIMZE) -g
CFLAGS += -std=c11 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__=1 
CFLAGS += -DPROM_LOG_ENABLE -DVERSION=\"$(VERSION)\"
CFLAGS += $(CFLAGS_$(OS))

LIBS_SunOS = -lnsl
LIBS_Linux =
LIBS_libprom += $(shell [ -d ../libprom/prom/build ] && printf -- '-L ../libprom/prom/build' )
LIBS ?= $(LIBS_$(OS)) $(LIBS_libprom)
LIBS += -lmicrohttpd -lprom

LDFLAGS_cc := -zdefs -Bdirect -zdiscard-unused=dependencies $(LIBS)
LDFLAGS_gcc := -zdefs -Wl,--as-needed $(LIBS)
LDFLAGS ?= -m$(MACH) $(LDFLAGS_$(CC))
RPATH_OPT_cc := -R
RPATH_OPT_gcc := -Wl,-rpath=
RPATH_OPT := $(RPATH_OPT_$(CC))

LIBCFLAGS = $(CFLAGS) $(LDFLAGS) -lc

PROGS= fstatmex

PROGSRCS = main.c
PROGOBJS = $(PROGSRCS:%.c=%.o) 

all: $(PROGS)

$(PROGS):   Makefile $(PROGOBJS)
	$(CC) -o $@ $(PROGOBJS) $(LDFLAGS)

.PHONY: clean distclean install depend

# for maintainers to get _all_ deps wrt. source headers properly honored
DEPENDFILE := makefile.dep

depend: $(DEPENDFILE)

# on Ubuntu, makedepend is included in the 'xutils-dev' package
$(DEPENDFILE): *.c *.h
	makedepend -f - -Y/usr/include *.c 2>/dev/null | \
        sed -e 's@/usr/include/[^ ]*@@g' -e '/: *$$/ d' >makefile.dep

clean:
	rm -f *.o *~ $(PROGS) \
		core gmon.out a.out man.1

distclean: clean
	rm -f $(DEPENDFILE) *.rej *.orig

install: $(PROGS)
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/$(MANDIR)
	$(INSTALL) -m 755 $(PROGS) $(DESTDIR)$(PREFIX)/$(BINDIR)
	$(INSTALL) -m 644 fstatex.8 $(DESTDIR)$(PREFIX)/$(MANDIR)/fstatex.8

-include $(DEPENDFILE)
