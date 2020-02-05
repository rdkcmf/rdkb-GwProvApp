##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -DCONFIG_PRIMARY_NET_BRIDGE_MODE
if PLATFORM_RASPBERRYPI_ENABLED
AM_LDFLAGS = -lsysevent
else
AM_LDFLAGS = -lgwprovappabs
AM_LDFLAGS += -lsysevent
endif
AM_LDFLAGS += -lsyscfg
AM_LDFLAGS += -lulog

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = gw_prov_utopia
gw_prov_utopia_CPPFLAGS = -I/var/tmp/pc-rdkb/include $(CPPFLAGS) -I$(srcdir)/include -I${PKG_CONFIG_SYSROOT_DIR}/$(includedir)/ruli/
gw_prov_utopia_SOURCES = gw_prov_sm.c
if PLATFORM_RASPBERRYPI_ENABLED
gw_prov_utopia_LDFLAGS = -lsysevent -lsyscfg -lulog
else
gw_prov_utopia_LDFLAGS =  -lgwprovappabs -lsysevent -lsyscfg -lulog
endif
gw_prov_utopia_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 -I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include
