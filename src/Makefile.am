AM_CFLAGS = $(VARNISHAPI_CFLAGS) $(VARNISHAPI_LIBS) -lcrypto

# Modules

vmod_LTLIBRARIES = \
	libvmod_pat.la

libvmod_pat_la_LDFLAGS = $(VMOD_LDFLAGS)
libvmod_pat_la_SOURCES = vmod_pat.c base64_url.c
nodist_libvmod_pat_la_SOURCES = \
	vcc_pat_if.c \
	vcc_pat_if.h

@BUILD_VMOD_PAT@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VARNISHAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"

TESTS = \
	vtc/vmod_pat.vtc

# Documentation

dist_doc_DATA = \
	vmod_pat.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_pat.3


.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
