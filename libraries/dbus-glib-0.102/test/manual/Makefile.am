AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/test/core \
	-I$(top_builddir)/test/core \
	$(DBUS_CFLAGS) \
	$(DBUS_GLIB_CFLAGS) \
	$(NULL)

LDADD = \
	$(top_builddir)/dbus/libdbus-glib-1.la \
	$(DBUS_LIBS) \
	$(DBUS_GLIB_LIBS) \
	$(NULL)

noinst_PROGRAMS = \
	$(NULL)

if DBUS_BUILD_TESTS
noinst_PROGRAMS += \
	test-invalid-usage \
	$(NULL)
endif

# This "test" exercises invalid usage. It is deliberately not run in
# TESTS, because it's (by design) full of bugs.
test_invalid_usage_SOURCES = \
	../core/my-object-marshal.c \
	../core/my-object-marshal.h \
	../core/my-object.c \
	../core/my-object.h \
	invalid-usage.c
