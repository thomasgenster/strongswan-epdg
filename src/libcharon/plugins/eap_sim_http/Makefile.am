AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libsimaka

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

libstrongswan_eap_sim_http_la_LDFLAGS = -module -avoid-version
libstrongswan_eap_sim_http_la_LIBADD = -lcurl

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-sim-http.la
else
plugin_LTLIBRARIES = libstrongswan-eap-sim-http.la
libstrongswan_eap_sim_http_la_LIBADD += $(top_builddir)/src/libsimaka/libsimaka.la
endif

libstrongswan_eap_sim_http_la_SOURCES = \
    eap_sim_http_plugin.h eap_sim_http_plugin.c \
    eap_sim_http_card.h eap_sim_http_card.c
