AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -D_COSA_SIM_
AM_LDFLAGS = -lgwprovappabs
AM_LDFLAGS += -lsysevent
AM_LDFLAGS += -lsyscfg
AM_LDFLAGS += -lulog

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = gw_prov_utopia
gw_prov_utopia_CPPFLAGS = -I/var/tmp/pc-rdkb/include $(CPPFLAGS)
gw_prov_utopia_SOURCES = gw_prov_sm.c
gw_prov_utopia_LDFLAGS =  -lgwprovappabs -lsysevent -lsyscfg -lulog