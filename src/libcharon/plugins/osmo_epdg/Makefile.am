AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libsimaka

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

libstrongswan_osmo_epdg_la_LDFLAGS = -module -avoid-version
libstrongswan_osmo_epdg_la_LIBADD = -lgmp -losmogsm

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-osmo-epdg.la
else
plugin_LTLIBRARIES = libstrongswan-osmo-epdg.la
libstrongswan_osmo_epdg_la_LIBADD += $(top_builddir)/src/libsimaka/libsimaka.la
endif

libstrongswan_osmo_epdg_la_SOURCES = \
	osmo_epdg_plugin.h osmo_epdg_plugin.c \
	osmo_epdg_provider.h osmo_epdg_provider.c \
	osmo_epdg_listener.h osmo_epdg_listener.c \
	gsup_client.h gsup_client.c \
	ipa_client.h ipa_client.c \
	osmo_epdg_utils.h osmo_epdg_utils.c \
	osmo_epdg_ue.h osmo_epdg_ue.c \
	osmo_epdg_db.h osmo_epdg_db.c
