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
AM_CFLAGS =
AM_CFLAGS += -DCONFIG_PRIMARY_NET_BRIDGE_MODE

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = gw_prov_utopia

if FEATURE_RDKB_WAN_MANAGER
gw_prov_utopia_SOURCES = gw_prov_sm_generic.c
else
gw_prov_utopia_SOURCES = gw_prov_sm.c autowan.c
endif

gw_prov_utopia_CPPFLAGS = -I$(srcdir)/include
gw_prov_utopia_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 -I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include

gw_prov_utopia_LDFLAGS = -lsysevent -lsyscfg -lulog -lsecure_wrapper -ltelemetry_msgsender -lpthread

if !PLATFORM_RASPBERRYPI_ENABLED
if !FEATURE_RDKB_WAN_MANAGER
if !PLATFORM_PUMA7_ENABLED
gw_prov_utopia_LDFLAGS += -lgwprovappabs
endif
endif
endif

if FEATURE_RDKB_WAN_MANAGER
gw_prov_utopia_LDFLAGS += -lhal_ethsw
endif

if WITH_GTEST_SUPPORT
SUBDIRS = test
endif
