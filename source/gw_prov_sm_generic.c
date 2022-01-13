/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#define _GW_PROV_SM_C_

/*! \file gw_prov_sm.c
    \brief gw provisioning
*/

/**************************************************************************/
/*      INCLUDES:                                                         */
/**************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#if !defined(_PLATFORM_RASPBERRYPI_)
#include <sys/types.h>
#endif
#include <unistd.h>
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(INTEL_PUMA7)
#include <ruli.h>
#endif
#include <sysevent/sysevent.h>
#if defined(INTEL_PUMA7)
#include "CC-ARM/sys_types.h"
#include "CC-ARM/sys_nettypes.h"
#include "generic_tlv_parser.h"
#endif
#include <syscfg/syscfg.h>
#include <pthread.h>
#include "Tr69_Tlv.h"
#include <autoconf.h>
#ifdef AUTOWAN_ENABLE
#include "autowan.h"
#include "gw_prov_sm.h"
#endif
#include <time.h>
#include "secure_wrapper.h"
#ifdef FEATURE_SUPPORT_RDKLOG
#include "rdk_debug.h"
#endif

#include "ccsp_hal_ethsw.h"
#include <telemetry_busmessage_sender.h>
#include "safec_lib_common.h"

#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
#include "platform_hal.h"
#endif
//Added for lxcserver thread function
#if defined(_PLATFORM_RASPBERRYPI_)
#define PORT 8081
#endif

#define WHITE	0
#define RED	3
#define SOLID	0
#define BLINK	1

/**************************************************************************/
/*      DEFINES:                                                          */
/**************************************************************************/

/* ETH WAN Fallback Interface Name - Should eventually move away from Compile Time */
#if defined (_XB7_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_)
#define ETHWAN_DEF_INTF_NAME "eth3"
#elif defined (INTEL_PUMA7)
#define ETHWAN_DEF_INTF_NAME "nsgmii0"
#elif defined(_PLATFORM_TURRIS_)
#define ETHWAN_DEF_INTF_NAME "eth2"
#elif defined(_CBR2_PRODUCT_REQ_)
#define ETHWAN_DEF_INTF_NAME "eth5"
#else
#define ETHWAN_DEF_INTF_NAME "eth0"
#endif

#define ERNETDEV_MODULE "/fss/gw/lib/modules/3.12.14/drivers/net/erouter_ni.ko"
#define NETUTILS_IPv6_GLOBAL_ADDR_LEN     	 128
#define ER_NETDEVNAME "erouter0"
#define IFNAME_WAN_0    "wan0"
#define IFNAME_ETH_0    "eth0"
#define TLV202_42_FAVOR_DEPTH 1
#define TLV202_42_FAVOR_WIDTH 2

/*! New implementation*/

#define BRMODE_ROUTER 0
#define BRMODE_PRIMARY_BRIDGE   3
#define BRMODE_GLOBAL_BRIDGE 2

#define ARGV_NOT_EXIST 0
#define ARGV_DISABLED 1
#define ARGV_ENABLED 3

#define INFINITE_LIFE_TIME 0xFFFFFFFF
#define MAX_CFG_PATH_LEN 256
#define MAX_CMDLINE_LEN 255

/* Restrict the log interval based on custom time */
#define LOGGING_INTERVAL_SECS    ( 60 * 60 )

#define DOCSIS_MULTICAST_PROC_MDFMODE "/proc/net/dbrctl/mdfmode"
#define DOCSIS_MULTICAST_PROC_MDFMODE_ENABLED "Enable"
#define TR69_TLVDATA_FILE "/nvram/TLVData.bin"
#define DEBUG_INI_NAME  "/etc/debug.ini"
#ifdef COMP_NAME
 #undef COMP_NAME
#endif
#define COMP_NAME "LOG.RDK.GWPROV"
#define LOG_INFO 4

#ifdef MULTILAN_FEATURE
/* Syscfg keys used for calculating mac addresses of local interfaces and bridges */
#define BASE_MAC_SYSCFG_KEY                  "base_mac_address"
/* Offset at which LAN bridge mac addresses will start */
#define BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY    "base_mac_bridge_offset"
#define BASE_MAC_BRIDGE_OFFSET               0
/* Offset at which wired LAN mac addresses will start */
#define BASE_MAC_LAN_OFFSET_SYSCFG_KEY       "base_mac_lan_offset"
#define BASE_MAC_LAN_OFFSET                  129
/* Offset at which WiFi AP mac addresses will start */
#define BASE_MAC_WLAN_OFFSET_SYSCFG_KEY      "base_mac_wlan_offset"
#define BASE_MAC_WLAN_OFFSET                 145
#endif

#ifdef FEATURE_SUPPORT_RDKLOG
void GWPROV_PRINT(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    RDK_LOG1(LOG_INFO, COMP_NAME, format, args);
    va_end(args);
}
#else
#define GWPROV_PRINT printf
#endif

#if defined(AUTOWAN_ENABLE) && defined(INTEL_PUMA7)
#define ETHWAN_FILE     "/nvram/ETHWAN_ENABLE"
#endif

static void _get_shell_output (FILE *fp, char *buf, int len);

/* New implementation !*/

#ifdef MULTILAN_FEATURE
#define BRG_INST_SIZE 5
#define BUF_SIZE 256
#endif
typedef enum
{
    DOCESAFE_ENABLE_DISABLE_extIf,
    DOCESAFE_ENABLE_IPv4_extIf,
    DOCESAFE_ENABLE_IPv6_extIf,
    DOCESAFE_ENABLE_IPv4_IPv6_extIf,

    DOCESAFE_ENABLE_NUM_ENABLE_TYPES_extIf
} DOCSIS_Esafe_Db_extIf_e;

typedef enum {
    EROUTER_MODE_INTERNAL,
    EROUTER_MODE,
    IPV4STATUS,
    IPV6STATUS,
    SYSTEM_RESTART,
    BRING_LAN,
    PNM_STATUS,
    PING_STATUS,
    CONN_STATUS,
    SNMP_SUBAGENT_STATUS,
    PRIMARY_LAN_13NET,
    LAN_STATUS,
    BRIDGE_STATUS,
    DHCPV6_CLIENT_V6ADDR,
    WAN_STATUS,
    IPV6_PREFIX,
    NTP_TIME_SYNC,
    FIREWALL_RESTART,
    WEBUI_FLAG_RESET,
    GWP_THREAD_ERROR
} eGwpThreadType;

typedef enum WanMode
{
    WAN_MODE_AUTO = 0,
    WAN_MODE_ETH,
    WAN_MODE_DOCSIS,
    WAN_MODE_UNKNOWN
}WanMode_t;

typedef struct
{
    char         *msgStr; 
    eGwpThreadType mType;       
} GwpThread_MsgItem;

GwpThread_MsgItem gwpthreadMsgArr[] = {
    {"erouterModeInternal",                        EROUTER_MODE_INTERNAL},
    {"erouter_mode",                               EROUTER_MODE},
    {"ipv4-status",                                IPV4STATUS},
    {"ipv6-status",                                IPV6STATUS},
    {"system-restart",                             SYSTEM_RESTART},
    {"bring-lan",                                  BRING_LAN},
    {"pnm-status",                                 PNM_STATUS},
    {"ping-status",                                PING_STATUS},
    {"conn-status",                                CONN_STATUS},
    {"snmp_subagent-status",                       SNMP_SUBAGENT_STATUS},
    {"primary_lan_l3net",                          PRIMARY_LAN_13NET},
    {"lan-status",                                 LAN_STATUS},
    {"bridge-status",                              BRIDGE_STATUS},
    {"tr_" ER_NETDEVNAME "_dhcpv6_client_v6addr",  DHCPV6_CLIENT_V6ADDR},
    {"wan-status",                                 WAN_STATUS},
    {"ipv6_prefix",                                IPV6_PREFIX},
    {"ntp_time_sync",                              NTP_TIME_SYNC},
    {"firewall-restart",                           FIREWALL_RESTART},
    {"webuiStartedFlagReset",                      WEBUI_FLAG_RESET}};

/**************************************************************************/
/*      LOCAL DECLARATIONS:                                               */
/**************************************************************************/

static void check_lan_wan_ready();

/* New implementation !*/
static void LAN_start();


void GWP_Util_get_shell_output( char * cmd, char *out, int len );

void setGWP_ipv4_event();

void setGWP_ipv6_event();


/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/


static int pnm_inited = 0;
static int netids_inited = 0;

static int hotspot_started = 0;
static int lan_telnet_started = 0;

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int ciscoconnect_started = 0;
#endif

static int webui_started = 0;
static unsigned int factory_mode = 0;
static int bridgeModeInBootup = 0;


static DOCSIS_Esafe_Db_extIf_e eRouterMode = DOCESAFE_ENABLE_DISABLE_extIf;
static DOCSIS_Esafe_Db_extIf_e oldRouterMode;
static int sysevent_fd;
static token_t sysevent_token;
#if !defined(AUTOWAN_ENABLE)
static int sysevent_fd_gs;
static token_t sysevent_token_gs;
#else
int sysevent_fd_gs;
token_t sysevent_token_gs;
#endif
static pthread_t sysevent_tid;
#if defined(_PLATFORM_RASPBERRYPI_)
static pthread_t linkstate_tid;
static pthread_t lxcserver_tid;
#endif
static int once = 0;
static int bridge_mode = BRMODE_ROUTER;
static int active_mode = BRMODE_ROUTER;

unsigned char ethwan_ifname[ 64 ];
static int ethwan_enabled = 0;

static void GWPEthWan_EnterBridgeMode(void);
static void GWPEthWan_EnterRouterMode(void);
/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
int IsEthWanEnabled()
{
    char buf[32];

    memset(buf,0,sizeof(buf));
    if (0 == access( "/nvram/ETHWAN_ENABLE" , F_OK ))
    {
        if (syscfg_get(NULL, "eth_wan_enabled", buf, sizeof(buf)) == 0)
        {
            if (0 == strcmp(buf,"true"))
            {
                return 1;
            }
        }
    }
    return 0;
}

eGwpThreadType Get_GwpThreadType(char * name)
{
    errno_t rc       = -1;
    int     ind      = -1;
    eGwpThreadType ret = GWP_THREAD_ERROR;

    if (name != NULL && name[0] != '\0')
    {
        int i;
        for (i = 0; i < GWP_THREAD_ERROR; i++) {
            rc = strcmp_s(gwpthreadMsgArr[i].msgStr,strlen(gwpthreadMsgArr[i].msgStr),name,&ind);
            ERR_CHK(rc);

            if((ind==0) && (rc == EOK))
            {
                ret = gwpthreadMsgArr[i].mType;
                break;
            }
        }
    }

    return ret;
}

static int GWPEthWan_SysCfgGetInt(const char *name)
{
   char out_value[20];
   int outbufsz = sizeof(out_value);
        printf(" %s : name = %s \n", __FUNCTION__, name);
   if (!syscfg_get(NULL, name, out_value, outbufsz))
   {
        printf(" value = %s \n", out_value);
      return atoi(out_value);
   }
   else
   {
        printf(" syscfg get failed \n");
      return -1;
   }
}

static int GWPETHWAN_SysCfgSetInt(const char *name, int int_value)
{
   char value[20];

   snprintf(value,sizeof(value),"%d", int_value);
   GWPROV_PRINT(" %s : name = %s , value = %s \n", __FUNCTION__, name, value);
   return syscfg_set(NULL, name, value);
}

void validate_mode(int* bridge_mode)
{
    if((*bridge_mode != BRMODE_ROUTER) && (*bridge_mode != BRMODE_PRIMARY_BRIDGE) && (*bridge_mode != BRMODE_GLOBAL_BRIDGE))
    {
        GWPROV_PRINT(" SYSDB_CORRUPTION: bridge_mode = %d \n", *bridge_mode);
        GWPROV_PRINT(" SYSDB_CORRUPTION: Switching to Default Router Mode \n");
        *bridge_mode = BRMODE_ROUTER;

        GWPETHWAN_SysCfgSetInt("bridge_mode", *bridge_mode);
        if( syscfg_commit() != 0)
            GWPROV_PRINT(" %s : syscfg_commit not success \n", __FUNCTION__);

    }
    GWPROV_PRINT(" %s : bridge_mode = %d\n", __FUNCTION__, *bridge_mode);
 }

static int getSyseventBridgeMode(int erouterMode, int bridgeMode) {
        
    //Erouter mode takes precedence over bridge mode. If erouter is disabled, 
    //global bridge mode is returned. Otherwise partial bridge or router  mode
    //is returned based on bridge mode. Partial bridge keeps the wan active
    //for networks other than the primary.
    // router = 0
    // global bridge = 2
    // partial (pseudo) = 3

	/*
	 * Router/Bridge settings from utopia
		typedef enum {
			BRIDGE_MODE_OFF    = 0,
			BRIDGE_MODE_DHCP   = 1,
			BRIDGE_MODE_STATIC = 2,
			BRIDGE_MODE_FULL_STATIC = 3
		   
		} bridgeMode_t;
	 */	
	 
	if( erouterMode )
	{
		switch( bridgeMode )
		{
			case 2:
			{
				return BRMODE_GLOBAL_BRIDGE;
			}
			break; /* 2 */
		
			case 3:
			{
				return BRMODE_PRIMARY_BRIDGE;
			}
			break; /* 3 */
		
			default: /* 0 */
			{
				return BRMODE_ROUTER;
			}
			break;
		}
	}
	else
	{
		return BRMODE_GLOBAL_BRIDGE;
	}
}

static void GWPEthWan_EnterBridgeMode(void)
{
    //GWP_UpdateEsafeAdminMode(DOCESAFE_ENABLE_DISABLE);
    //DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_DISABLED);
    /* Reset Switch, to remove all VLANs */
    // GSWT_ResetSwitch();
    //DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_NOT_INITIATED);
    char MocaStatus[16]  = {0};
    char BridgeMode[2] = {0};
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    syscfg_get(NULL, "MoCA_current_status", MocaStatus, sizeof(MocaStatus));
    GWPROV_PRINT(" MoCA_current_status = %s \n", MocaStatus);
    if ((syscfg_set(NULL, "MoCA_previous_status", MocaStatus) != 0))
    {
        printf("syscfg_set failed\n");
    }
    else
    {
        if (syscfg_commit() != 0)
        {
            printf("syscfg_commit failed\n");
        }
    }
    v_secure_system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool false");
    snprintf(BridgeMode, sizeof(BridgeMode), "%d", active_mode);
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "bridge_mode", BridgeMode, 0);
    v_secure_system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool false");

    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "forwarding-restart", "", 0);
}

//Actually enter router mode
static void GWPEthWan_EnterRouterMode(void)
{
         /* Coverity Issue Fix - CID:71381 : UnInitialised varible */
    char MocaPreviousStatus[16] = {0};
        int prev;
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);

//    bridge_mode = 0;
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "bridge_mode", "0", 0);

    syscfg_get(NULL, "MoCA_previous_status", MocaPreviousStatus, sizeof(MocaPreviousStatus));
    prev = atoi(MocaPreviousStatus);
    GWPROV_PRINT(" MocaPreviousStatus = %d \n", prev);
    if(prev == 1)
    {
        v_secure_system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool true");
    }
    else
    {
        v_secure_system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool false");
    }

    v_secure_system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool true");

    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "forwarding-restart", "", 0);
}

static void UpdateActiveDeviceMode()
{
    bridge_mode = GWPEthWan_SysCfgGetInt("bridge_mode");
    active_mode = getSyseventBridgeMode(eRouterMode,bridge_mode);
}

static void GWPEthWan_ProcessUtopiaRestart(void)
{
    // This function is called when "system-restart" event is received, This
    // happens when WEBUI change bridge configuration. We do not restart the
    // whole system, only routing/bridging functions only

    int oldActiveMode = active_mode;

    bridge_mode = GWPEthWan_SysCfgGetInt("bridge_mode");
    //int loc_eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");

    active_mode = getSyseventBridgeMode(eRouterMode,bridge_mode);

    printf("bridge_mode = %d, active_mode = %d\n", bridge_mode, active_mode);
    GWPROV_PRINT(" bridge_mode = %d, active_mode = %d\n", bridge_mode, active_mode);

    if (oldActiveMode == active_mode) return; // Exit if no transition

    webui_started = 0;
    switch ( active_mode)
    {
        case BRMODE_ROUTER:
            GWPEthWan_EnterRouterMode();
            break;

        case BRMODE_GLOBAL_BRIDGE:
        case BRMODE_PRIMARY_BRIDGE:
            GWPEthWan_EnterBridgeMode();
            break;
        default:
        break;
    }

}

int IsFileExists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

#define TR069PidFile "/var/tmp/CcspTr069PaSsp.pid"
#ifdef FALSE
 #undef FALSE
#endif
#define FALSE 0
#ifdef TRUE
 #undef TRUE
#endif
#define TRUE 1



/* TR-069 MIB SUB OIDs */
#define GW_TR069_MIB_SUB_OID_ENABLE_CWMP                 0x01
#define GW_TR069_MIB_SUB_OID_URL                         0x02
#define GW_TR069_MIB_SUB_OID_USERNAME                    0x03
#define GW_TR069_MIB_SUB_OID_PASSWORD                    0x04
#define GW_TR069_MIB_SUB_OID_CONNREQ_USERNAME            0x05
#define GW_TR069_MIB_SUB_OID_CONNREQ_PASSWORD            0x06
#define GW_TR069_MIB_SUB_OID_ALLOW_DOCSIS_CONFIG         0x09  // not implemented yet - 03/31/2014

/* TR-069 MIB OID INSTANCE NUM */
#define GW_TR069_MIB_SUB_OID_INSTANCE_NUM                0x00

/* TR-069 MIB DATA TYPE */
#define GW_TR069_MIB_DATATYPE_BOOL                       0x02
#define GW_TR069_MIB_DATATYPE_STRING                     0x04

/* TR-069 MIB DATA TYPE LENGTH */
#define GW_TR069_MIB_DATATYPE_LEN_BOOL                   0x01

#define SNMP_DATA_BUF_SIZE 1000



/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/

/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgGetInt
 **************************************************************************
 *  \brief Get Syscfg Integer Value
 *  \return int/-1
 **************************************************************************/
static int GWP_SysCfgGetInt(const char *name)
{
   char out_value[20];
   int outbufsz = sizeof(out_value);
	GWPROV_PRINT(" %s : name = %s \n", __FUNCTION__, name);
   if (!syscfg_get(NULL, name, out_value, outbufsz))
   {
	GWPROV_PRINT(" value = %s \n", out_value);
      return atoi(out_value);
   }
   else
   {
	GWPROV_PRINT(" syscfg get failed \n");
      return -1;
   }
}

static void check_lan_wan_ready()
{
	char br_st[16] = { 0 };
	char lan_st[16] = { 0 };
	char wan_st[16] = { 0 };
	char ipv6_prefix[128] = { 0 };
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
        errno_t rc = -1;
        int ind = -1;
		
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "bridge-status", br_st, sizeof(br_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "lan-status", lan_st, sizeof(lan_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "wan-status", wan_st, sizeof(wan_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "ipv6_prefix", ipv6_prefix, sizeof(ipv6_prefix));

	printf("****************************************************\n");
	printf("       %s   %s   %s   %s  %d  %d                    \n", br_st, lan_st, wan_st, ipv6_prefix, eRouterMode, bridge_mode);
	printf("****************************************************\n");

	GWPROV_PRINT(" bridge-status = %s\n", br_st);
	GWPROV_PRINT(" lan-status = %s\n", lan_st);
	GWPROV_PRINT(" wan-status = %s\n", wan_st);
	GWPROV_PRINT(" ipv6_prefix = %s\n", ipv6_prefix);
	GWPROV_PRINT(" eRouterMode = %d\n", eRouterMode);
	if (eRouterMode == 2) {
		t2_event_d("SYS_INFO_ErouterMode2", 1);
	}
	GWPROV_PRINT(" bridge_mode = %d\n", bridge_mode);

	if (bridge_mode != 0 || eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
	{
                rc = strcmp_s("started", strlen("started"), br_st, &ind);
                ERR_CHK(rc);
                if ((!ind) && (rc == EOK))
		{
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
			once = 1;
		}
	}
	else
	{
		if (eRouterMode == DOCESAFE_ENABLE_IPv4_extIf)
		{
                        rc = strcmp_s("started", strlen("started"),lan_st, &ind);
                        ERR_CHK(rc);
                        if ((!ind) && (rc == EOK))
			{
                            rc = strcmp_s("started", strlen("started"),wan_st, &ind);
                            ERR_CHK(rc);
                            if ((!ind) && (rc == EOK))
                            {
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				once = 1;
			    }
                        }
		}
		else if (eRouterMode == DOCESAFE_ENABLE_IPv4_IPv6_extIf)
		{
			if (strlen(ipv6_prefix))
			{
                            rc = strcmp_s("started", strlen("started"),lan_st, &ind);
                            ERR_CHK(rc);
                            if ((!ind) && (rc == EOK))
                            {
                                rc = strcmp_s("started", strlen("started"),wan_st, &ind);
                                ERR_CHK(rc);
                                if ((!ind) && (rc == EOK))
				{
                                    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				    once = 1;
                                }
                             }
			}
		}
		else if (eRouterMode == DOCESAFE_ENABLE_IPv6_extIf)
		{
			if (strlen(ipv6_prefix))
			{
                            rc = strcmp_s("started", strlen("started"),lan_st, &ind);
                            ERR_CHK(rc);
                            if ((!ind) && (rc == EOK))
			    {
                            	sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				once = 1;
                            }
			}
		}
	}
}
void getMultiCastGroupAddress(unsigned char *inetAddr, unsigned char *inetMcgrpAddr)
{

    const unsigned char SolicitedNodeAddressPrefix[13]={0xff,02,00,00,00,00,00,00,00,00,01,0xff,00};
    int  i = 0;
    if ((inetAddr == NULL ) || (inetMcgrpAddr == NULL))
        return;

    // copy the 104 bit (13 byte) prefix
    for (i = 0; i <13; i++ )
    {
        inetMcgrpAddr[i] = SolicitedNodeAddressPrefix[i];
    }

    // now append the low-order 24 bits of *this* address to the prefix
    inetMcgrpAddr[13] = inetAddr[13];
    inetMcgrpAddr[14] = inetAddr[14];
    inetMcgrpAddr[15] = inetAddr[15];

    return;
}

/**************************************************************************/
/*! \fn void *GWP_sysevent_threadfunc(void *data)
 **************************************************************************
 *  \brief Function to process sysevent event
 *  \return 0
**************************************************************************/
static void *GWP_sysevent_threadfunc(void *data)
{
    async_id_t eroutermodeinternal_asyncid;
    async_id_t erouter_mode_asyncid;
    async_id_t webui_reset_asyncid;
    async_id_t ipv6_status_asyncid;
    async_id_t snmp_subagent_status_asyncid;
    async_id_t primary_lan_l3net_asyncid;
    async_id_t lan_status_asyncid;
    async_id_t bridge_status_asyncid;
    async_id_t wan_status_asyncid;
    async_id_t ipv6_prefix_asyncid;
    async_id_t pnm_asyncid;
#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
    async_id_t ping_status_asyncid;
    async_id_t conn_status_asyncid;
#endif
    async_id_t system_restart_asyncid;
    async_id_t firewall_restart_asyncid;
    async_id_t ntp_time_sync_asyncid;

    // char buf[10];
    time_t time_now = { 0 }, time_before = { 0 };
    // errno_t rc = -1;
    // int ind = -1;        

    GWPROV_PRINT(" Entry %s \n", __FUNCTION__); 
    sysevent_setnotification(sysevent_fd, sysevent_token, "erouterModeInternal", &eroutermodeinternal_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "erouter_mode", &erouter_mode_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "webuiStartedFlagReset",  &webui_reset_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6-status",  &ipv6_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "snmp_subagent-status",  &snmp_subagent_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "primary_lan_l3net",  &primary_lan_l3net_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "lan-status",  &lan_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "wan-status",  &wan_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6_prefix",  &ipv6_prefix_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "bridge-status",  &bridge_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "tr_" ER_NETDEVNAME "_dhcpv6_client_v6addr",  &ipv6_status_asyncid);
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
    sysevent_setnotification(sysevent_fd, sysevent_token, "bring-lan",  &pnm_asyncid);
#else
    sysevent_setnotification(sysevent_fd, sysevent_token, "pnm-status",  &pnm_asyncid);
#endif

#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
    sysevent_setnotification(sysevent_fd, sysevent_token, "ping-status",  &ping_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "conn-status",  &conn_status_asyncid);
#endif
    sysevent_set_options    (sysevent_fd, sysevent_token, "ntp_time_sync", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ntp_time_sync",  &ntp_time_sync_asyncid);
    sysevent_set_options(sysevent_fd, sysevent_token, "firewall-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "firewall-restart",  &firewall_restart_asyncid);

    sysevent_setnotification(sysevent_fd, sysevent_token, "system-restart",  &system_restart_asyncid);
    sysevent_set_options(sysevent_fd, sysevent_token, "system-restart", TUPLE_FLAG_EVENT);
    GWPROV_PRINT(" Set notifications done \n");    
    //     sysevent_get(sysevent_fd, sysevent_token, "homesecurity_lan_l3net", buf, sizeof(buf));
    //     if (buf[0] != '\0' && atoi(buf))
    //         netids_inited = 1;
    //     
    //     sysevent_get(sysevent_fd, sysevent_token, "snmp_subagent-status", buf, sizeof(buf));
    //     if (buf[0] != '\0')
    //     {
    //         rc = strcmp_s("started", strlen("started"),buf, &ind);
    //         ERR_CHK(rc);
    //         if ((ind == 0) && (rc == EOK))
    //         {
    //            snmp_inited = 1;
    //         }
    //     } 
    //     
    //     if(netids_inited && snmp_inited && !factory_mode) {
    //         LAN_start();
    //     }
    for (;;)
    {
#ifdef MULTILAN_FEATURE
        char name[40], val[42], buf[BUF_SIZE];
#else
        char name[40], val[42];
#ifdef CONFIG_CISCO_HOME_SECURITY
        char  buf[10];
#endif

#endif
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_asyncid;
        errno_t rc = -1;
        int ind = -1;
#ifdef MULTILAN_FEATURE
        errno_t rc1 = -1;
        int ind1 = -1;
        char brlan0_inst[BRG_INST_SIZE] = {0};
        char brlan1_inst[BRG_INST_SIZE] = {0};
        char* l3net_inst = NULL;
#endif


#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
        LEDMGMT_PARAMS ledMgmt;
        FILE *responsefd=NULL;
        char *networkResponse = "/var/tmp/networkresponse.txt";
        int iresCode = 0 , iRet = 0;
        char responseCode[10]={0}, cp_enable[10]={0}, redirect_flag[10]={0}, currentWanInterface[10]={0}, defaultWanInterface[10]={0};
#endif
        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if (err)
        {
            /* 
             * Log should come for every 1hour 
             * - time_now = getting current time 
             * - difference between time now and previous time is greater than 
             -	     *    3600 seconds
             * - time_before = getting current time as for next iteration 
             *    checking		     
             */	
            time(&time_now);

            if(LOGGING_INTERVAL_SECS <= ((unsigned int)difftime(time_now, time_before)))
            {
                printf("%s-ERR: %d\n", __func__, err);
                time(&time_before);
            }

            sleep(10);
        }
        else
        {
            GWPROV_PRINT(" %s : name = %s, val = %s \n", __FUNCTION__, name, val );
            eGwpThreadType ret_value;
            ethwan_enabled = IsEthWanEnabled();
            ret_value = Get_GwpThreadType(name);
            if (ret_value == WEBUI_FLAG_RESET)
            {
                webui_started = 0;
            }
            else if (ret_value == SYSTEM_RESTART)
            {
                GWPROV_PRINT("gw_prov_sm: got system restart\n");                
                if (ethwan_enabled)
                {
                    GWPEthWan_ProcessUtopiaRestart();
                }
                else
                {
                    // CM agent handles router/bridge mode toggle in Docsis wan mode
                    // Here only update active mode variable.
                    UpdateActiveDeviceMode();
                }
            }
            else if (ret_value == IPV6STATUS)
            {
                if (ethwan_enabled)
                {
                    rc = strcmp_s("up", strlen("up"),val, &ind);
                    ERR_CHK(rc);
                    if ((ind == 0) && (rc == EOK))
                    {
                        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "sshd-restart", "", 0);

                    }
                }
            }
            else if (ret_value == NTP_TIME_SYNC)
            {
                if (ethwan_enabled)
                {
                    GWPROV_PRINT("ntp time syncd, need to restart sshd %s\n", name);
                    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "sshd-restart", "", 0);
                }
            }
            else if (ret_value == FIREWALL_RESTART)            
            {
                if (ethwan_enabled)
                {
                    GWPROV_PRINT("received notification event %s\n", name);
                    v_secure_system( "ip6tables -I OUTPUT -o %s -p icmpv6 -j DROP", ethwan_ifname);
                }
            }
            else if (ret_value == EROUTER_MODE)
            {
                oldRouterMode = eRouterMode;
                eRouterMode = atoi(val);

                if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf &&
                    eRouterMode != DOCESAFE_ENABLE_IPv4_extIf    &&
                    eRouterMode != DOCESAFE_ENABLE_IPv6_extIf    &&
                    eRouterMode != DOCESAFE_ENABLE_IPv4_IPv6_extIf)
                {
                    eRouterMode = DOCESAFE_ENABLE_DISABLE_extIf;
                }
            }
            else if (ret_value == EROUTER_MODE_INTERNAL)
            {
                oldRouterMode = eRouterMode;
                eRouterMode = atoi(val);
            }
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
            else if (ret_value == BRING_LAN)           
#else
            else if (ret_value == PNM_STATUS)
#endif 
            {
                GWPROV_PRINT(" bring-lan/pnm-status received \n");                
                pnm_inited = 1;
                if (netids_inited) {
                    LAN_start();
                }
            }
#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
            else if ( (ret_value == PING_STATUS) || ( ret_value == CONN_STATUS ) )
            {
                rc =  memset_s(&ledMgmt,sizeof(LEDMGMT_PARAMS), 0, sizeof(LEDMGMT_PARAMS));
                ERR_CHK(rc);
                if ( ret_value == PING_STATUS )
                {
                    GWPROV_PRINT("Received ping-status event notification, ping-status value is %s\n", val);
                    rc = strcmp_s("missed", strlen("missed"),val, &ind);
                }
                else
                {
                    GWPROV_PRINT("Received conn-status event notification, conn-status value is %s\n", val);
                    rc = strcmp_s("failed", strlen("failed"),val, &ind);
                }
                ERR_CHK(rc);
                if ((ind == 0) && (rc == EOK))
                {

#if defined(_CBR2_PRODUCT_REQ_)
                    ledMgmt.LedColor = WHITE;
                    ledMgmt.State	 = BLINK;
                    ledMgmt.Interval = 5;
                    if ( ret_value == PING_STATUS )
                    {
                        GWPROV_PRINT("Ping missed, Setting LED to WHITE FAST BLINK\n");
                    }
                    else
                    {
                        GWPROV_PRINT("Connection failed, Setting LED to WHITE FAST BLINK\n");
                    }
#else
                    ledMgmt.LedColor = RED;
                    ledMgmt.State	 = SOLID;
                    ledMgmt.Interval = 0;
                    if ( ret_value == PING_STATUS )
                    {
                        GWPROV_PRINT("Ping missed, Setting LED to RED\n");
                    }
                    else
                    {
                        GWPROV_PRINT("Connection failed, Setting LED to RED\n");
                    }
#endif

                    if(0 != platform_hal_setLed(&ledMgmt)) {

                        GWPROV_PRINT("platform_hal_setLed failed\n");
                    }

                    // Set LED state to RED
                }
                else 
                {
                    if ( ret_value == PING_STATUS )
                    {
                        rc = strcmp_s("received", strlen("received"),val, &ind);
                    }
                    else
                    {
                        rc = strcmp_s("success", strlen("success"),val, &ind);
                    }
                    ERR_CHK(rc);
                    if ((ind == 0) && (rc == EOK))
                    {
                        //get default wan interface
                        sysevent_get(sysevent_fd_gs, sysevent_token_gs, "wan_ifname", defaultWanInterface, sizeof(defaultWanInterface));
                        GWPROV_PRINT("Default wan interface: '%s'.\n", defaultWanInterface);
                        //check whether current wan interface is LTE or not
                        sysevent_get(sysevent_fd_gs, sysevent_token_gs, "current_wan_ifname", currentWanInterface, sizeof(currentWanInterface));
                        GWPROV_PRINT("Current wan interface: '%s'.\n", currentWanInterface);

                        rc = strcmp_s(defaultWanInterface, strlen(defaultWanInterface),currentWanInterface, &ind);
                        ERR_CHK(rc);
                        if ((ind == 0) && (rc == EOK))
                        {
                          // Set LED if the current wan interface is not LTE
                          // Set LED state based on whether device is in CP or not
                          GWPROV_PRINT("Current wan interface is default one.\n");
                          GWPROV_PRINT("Setting LED: SOLID WHITE\n");
                          ledMgmt.LedColor = WHITE;
                          ledMgmt.State  = SOLID;
                          ledMgmt.Interval = 0;
                        }
                        else {
                          GWPROV_PRINT("Current wan interface is not default one.\n");
                        }
                        

                        iRet = syscfg_get(NULL, "CaptivePortal_Enable", cp_enable, sizeof(cp_enable));

                        if ( iRet == 0  )
                        {
                            rc = strcmp_s("true", strlen("true"),cp_enable, &ind);
                            ERR_CHK(rc);
                            if ((ind == 0) && (rc == EOK))
                            {
                                iRet=0;
                                iRet = syscfg_get(NULL, "redirection_flag", redirect_flag, sizeof(redirect_flag));
                                if (  iRet == 0  )
                                {
                                    rc = strcmp_s("true", strlen("true"),redirect_flag, &ind);
                                    ERR_CHK(rc);
                                    if ((ind == 0) && (rc == EOK))
                                    {
                                        if((responsefd = fopen(networkResponse, "r")) != NULL)
                                        {
                                            if(fgets(responseCode, sizeof(responseCode), responsefd) != NULL)
                                            {
                                                iresCode = atoi(responseCode);
                                            }

                                            fclose(responsefd);
                                            responsefd = NULL;
                                            if ( 204 == iresCode )
                                            {
                                                /*Check NotifyWifiChanges is true to make sure device in captive portal*/
                                                FILE *fp;
                                                char buf[256];
                                                fp = v_secure_popen("r", "psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges");
                                                _get_shell_output(fp, buf, sizeof(buf));
                                                rc = strcmp_s("true", strlen("true"),buf, &ind);
                                                ERR_CHK(rc);
                                                if ((ind == 0) && (rc == EOK))
                                                {
                                                    GWPROV_PRINT("NotifyWiFiChanges is true\n");
                                                    ledMgmt.State	 = BLINK;
                                                    ledMgmt.Interval = 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if ( BLINK == ledMgmt.State )
                        {
                            GWPROV_PRINT("Device is in Captive Portal, setting WHITE LED to blink\n");
                        }
                        else
                        {
                            GWPROV_PRINT("Device is not in Captive Portal, setting LED to SOLID WHITE \n");
                        }

                        if(0 != platform_hal_setLed(&ledMgmt)) {
                            GWPROV_PRINT("platform_hal_setLed failed\n");

                        }
                    }
                }
            }
#endif
            /*else if (ret_value == SNMP_SUBAGENT_STATUS && !snmp_inited)
              {

              snmp_inited = 1;
              if (netids_inited) {
              if(!factory_mode)
              LAN_start();
              }
              }*/ 
              else if (ret_value == PRIMARY_LAN_13NET)
              {
                  GWPROV_PRINT(" primary_lan_l3net received \n");
                  if (pnm_inited)
                  {

#if defined (_PROPOSED_BUG_FIX_)
                      GWPROV_PRINT("***STARTING LAN***\n");
#endif

                      LAN_start();
                  }
                  netids_inited = 1;
              }
              else if (ret_value == LAN_STATUS || ret_value == BRIDGE_STATUS ) 
              {
#if defined (_PROPOSED_BUG_FIX_)
                  GWPROV_PRINT("***LAN STATUS/BRIDGE STATUS RECIEVED****\n");
                  GWPROV_PRINT("THE EVENT =%s VALUE=%s\n",name,val);
#endif
                  rc = strcmp_s("started", strlen("started"),val, &ind);
                  ERR_CHK(rc);
                  if ((ind == 0) && (rc == EOK)){
                      if (!webui_started) { 
#if defined(_PLATFORM_RASPBERRYPI_)

                          rc = strcmp_s("bridge-status", strlen("bridge-status"),name, &ind);
                          ERR_CHK(rc);
                          if ((ind == 0) && (rc == EOK)) {
                              GWP_DisableERouter();
                          }
                          v_secure_system("/bin/sh /etc/webgui.sh");
#elif defined(_COSA_INTEL_XB3_ARM_) || defined(_CBR_PRODUCT_REQ_)
                          // For other devices CcspWebUI.service launches the GUI processes
                          startWebUIProcess();
#else
                          if ((ret_value == BRIDGE_STATUS) && (!bridgeModeInBootup))
                          {
                              char output[ 32 ] = { 0 };
                              memset(output,0,sizeof(output));
                              GWPROV_PRINT(" bridge-status = %s start webgui.sh \n", val );
                              v_secure_system("/bin/sh /etc/webgui.sh &");
                          }
#endif
                          webui_started = 1 ;
#ifdef CONFIG_CISCO_HOME_SECURITY
                          //Piggy back off the webui start event to signal XHS startup
                          sysevent_get(sysevent_fd_gs, sysevent_token_gs, "homesecurity_lan_l3net", buf, sizeof(buf));
                          if (buf[0] != '\0') sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv4-up", buf, 0);
#endif

#if defined(RDK_ONEWIFI) && (defined(_XB6_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_))
        GWPROV_PRINT("CALL VLAN UTIL TO SET UP LNF\n");
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "lnf-setup","6", 0);
#endif 
                      }
#ifdef MULTILAN_FEATURE
                      sysevent_get(sysevent_fd_gs, sysevent_token_gs, "primary_lan_l3net", brlan0_inst, sizeof(brlan0_inst));
                      sysevent_get(sysevent_fd_gs, sysevent_token_gs, "homesecurity_lan_l3net", brlan1_inst, sizeof(brlan1_inst));
                      /*Get the active bridge instances and bring up the bridges */
                      sysevent_get(sysevent_fd_gs, sysevent_token_gs, "l3net_instances", buf, sizeof(buf));
                      l3net_inst = strtok(buf, " ");
                      while(l3net_inst != NULL)
                      {
                          rc = strcmp_s(l3net_inst, strlen(l3net_inst),brlan0_inst, &ind);
                          ERR_CHK(rc);
                          rc1 = strcmp_s(l3net_inst, strlen(l3net_inst),brlan1_inst, &ind1);
                          ERR_CHK(rc1);
                          /*brlan0 and brlan1 are already up. We should not call their instances again*/
                          if(!(((ind == 0) && (rc == EOK)) || ((ind1 == 0) && (rc1 == EOK))))
                          {
                              sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv4-up", l3net_inst, 0);
                          }
                          l3net_inst = strtok(NULL, " ");
                      }
#endif

                      if (!hotspot_started) {
#if defined(INTEL_PUMA7) || defined(_COSA_BCM_MIPS_) || defined(_COSA_BCM_ARM_) ||  defined(_COSA_INTEL_XB3_ARM_)
                          printf("Not Calling hotspot-start for XB3,XB6 and CBR it will be done in \
                                  cosa_start_rem.sh,hotspot.service and xfinity_hotspot_bridge_setup.sh respectively\n");
#else
                          sysevent_set(sysevent_fd_gs, sysevent_token_gs, "hotspot-start", "", 0);
                          hotspot_started = 1 ;
#endif
                      } 

                      if (factory_mode && lan_telnet_started == 0) {
                          v_secure_system("/usr/sbin/telnetd -l /usr/sbin/cli -i brlan0");
                          lan_telnet_started=1;
                      }
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT

                      if (!ciscoconnect_started) { 
                          sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ciscoconnect-restart", "", 0);
                          ciscoconnect_started = 1 ;
                      }
#endif
                      if (!once) {
                          check_lan_wan_ready();
                      }
                      bridgeModeInBootup = 0; // reset after lan/bridge status is received.
                  }
              } else if (ret_value == DHCPV6_CLIENT_V6ADDR) {
                  unsigned char v6addr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(unsigned char) ] = {0};
                  /* Coverity Issue Fix - CID:79291 : UnInitialised varible  */
                  unsigned char soladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(unsigned char) ] = {0} ;
                  inet_pton(AF_INET6, val, v6addr);
#if !defined(_PLATFORM_RASPBERRYPI_)
                  getMultiCastGroupAddress(v6addr,soladdr);
#endif
                  inet_ntop(AF_INET6, soladdr, val, sizeof(val));


                  sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv6_"ER_NETDEVNAME"_dhcp_solicNodeAddr", val,0);

                  unsigned char lan_wan_ready = 0;
                  char result_buf[32];
                  result_buf[0] = '\0';

                  sysevent_get(sysevent_fd_gs, sysevent_token_gs, "start-misc", result_buf, sizeof(result_buf));
                  lan_wan_ready = strstr(result_buf, "ready") == NULL ? 0 : 1;

                  if(!lan_wan_ready) {
                      v_secure_system("ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", ER_NETDEVNAME, val);
                  }
                  else
                      sysevent_set(sysevent_fd_gs, sysevent_token_gs, "firewall-restart", "",0);
#ifdef DSLITE_FEATURE_SUPPORT
                  /* Modification for DSLite Service */
                  if(!strcmp(val, ""))//If erouter0 IPv6 address is null
                  {
                      v_secure_system("service_dslite stop &");
                  }
                  else
                  {
                      v_secure_system("service_dslite restart &");
                  }
#endif
              }
              else if (ret_value == WAN_STATUS) {
                  rc = strcmp_s("started", strlen("started"),val, &ind);
                  ERR_CHK(rc);
                  if ((!ind) && (rc == EOK))
                  { 
                      if (!once) {
                          check_lan_wan_ready();
                      }
                  }
                  if (ethwan_enabled)
                  {
                      if ((0 == ind) && (rc == EOK))
                      {
                          v_secure_system("sysctl -w net.ipv6.conf.%s.disable_ipv6=1", ethwan_ifname);
                          FILE * file = fopen("/tmp/phylink_wan_state_up", "wb");
                          if (file != NULL)
                              fclose(file);
                          else
                              printf("File /tmp/phylink_wan_state_up cannot be created\n");
                          sysevent_set(sysevent_fd_gs, sysevent_token_gs, "sshd-restart", "", 0);
                      }
                  }
              }
              else if (ret_value == IPV6_PREFIX && strlen(val) > 5) {
                  if (!once) {
                      check_lan_wan_ready();
                  }
              }
        }
    }
    return 0;
}


/* GWP_Util_get_shell_output() */
void GWP_Util_get_shell_output( char * cmd, char *out, int len )
{
    FILE  *fp = NULL;
    char   buf[ 16 ] = { 0 };
    char  *p = NULL;
    errno_t rc = -1;

    fp = popen( cmd, "r" );

    if ( fp )
    {
        if (fgets( buf, sizeof( buf ), fp ) == NULL)
           GWPROV_PRINT("%s fgets error \n", __FUNCTION__);
        
        /*we need to remove the \n char in buf*/
        if ( ( p = strchr( buf, '\n' ) ) ) 
		*p = 0;

        rc = strcpy_s(out, len, buf);
        if(rc != EOK)
        {
           ERR_CHK(rc);
	   pclose( fp );
           return;
        }         

        pclose( fp );        
    }
}


/**************************************************************************/
/*! \fn int DCR_act_ProvEntry(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions at entry to gw provisioning
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_act_ProvEntry()
{
    unsigned char buf[64];
    errno_t rc       = -1;
    int     ind      = -1;
    char sysevent_cmd[80];
    char BridgeMode[2] = {0};
    int sysevent_bridge_mode = 0;

    syscfg_init();
    if (0 != GWP_SysCfgGetInt("bridge_mode"))
    {
        bridgeModeInBootup = 1;
    }
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_provevt", &sysevent_token);
    sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_provevt-gs", &sysevent_token_gs);

    if (sysevent_fd >= 0)
    {
        GWPROV_PRINT(" Creating Thread  GWP_sysevent_threadfunc \n"); 
        pthread_create(&sysevent_tid, NULL, GWP_sysevent_threadfunc, NULL);
    }
    memset(buf,0,sizeof(buf));

    if (0 == access( "/nvram/ETHWAN_ENABLE" , F_OK ))
    {
        if (syscfg_get(NULL, "eth_wan_enabled", buf, sizeof(buf)) == 0)
        {
            rc = strcmp_s("false",strlen("false"),buf,&ind);
            ERR_CHK(rc);

            if((ind==0) && (rc == EOK))
            {
                if (syscfg_set(NULL, "eth_wan_enabled", "true") != 0)
                {
                    GWPROV_PRINT("eth_wan_enabled syscfg failed\n");
                }
                else
                {
                    if (syscfg_commit() != 0)
                    {
                        GWPROV_PRINT("eth_wan_enabled syscfg_commit\n");

                    }
                }
            }
        }
        v_secure_system("syscfg set last_wan_mode 1"); // to handle Factory reset case (1 = Ethwan mode)
        v_secure_system("syscfg set curr_wan_mode 1"); // to handle Factory reset case (1 = Ethwan mode)
        v_secure_system("syscfg commit");
        ethwan_enabled = 1;
    }
    else
    {
        int lastKnownWanMode = WAN_MODE_UNKNOWN; 
        memset(buf,0,sizeof(buf));
        if (syscfg_get(NULL, "last_wan_mode", buf, sizeof(buf)) == 0)
        {
            lastKnownWanMode = atoi(buf);
        }
        // Last known wan mode is ethernet but nvram file not available
        // so updating here last known mode as UNKNOWN and wan manager will search docsis wan first.
        if (WAN_MODE_ETH == lastKnownWanMode)
        {
            GWPROV_PRINT("last wan mode is ethernet but nvram file not available !\n");
            GWPROV_PRINT("Update last wan mode as unknown\n");
            snprintf(buf, sizeof(buf), "%d", WAN_MODE_UNKNOWN);
            if (syscfg_set(NULL, "last_wan_mode", buf) != 0)
            {
                GWPROV_PRINT("last_wan_mode syscfg failed\n");
            }
            else
            {
                if (syscfg_commit() != 0)
                {
                    GWPROV_PRINT("last_wan_mode syscfg_commit\n");

                }
            }
        }
    }

    //Get the ethwan interface name from HAL
    memset( ethwan_ifname , 0, sizeof( ethwan_ifname ) );

    if ( (0 != GWP_GetEthWanInterfaceName(ethwan_ifname, sizeof(ethwan_ifname)))
            || (0 == strnlen(ethwan_ifname,sizeof(ethwan_ifname)))
            || (0 == strncmp(ethwan_ifname,"disable",sizeof(ethwan_ifname)))
       )

    {
        //Fallback case needs to set it default
        memset( ethwan_ifname , 0, sizeof( ethwan_ifname ) );
        sprintf( ethwan_ifname , "%s", ETHWAN_DEF_INTF_NAME );
        GWPROV_PRINT(" Failed to get EthWanInterfaceName: %s \n", ethwan_ifname );
    }

    GWPROV_PRINT(" EthWanInterfaceName: %s \n", ethwan_ifname );

#if defined (_BRIDGE_UTILS_BIN_) && !defined (_WNXL11BWL_PRODUCT_REQ_)
    if ( syscfg_set( NULL, "eth_wan_iface_name", ethwan_ifname ) != 0 )
    {
        GWPROV_PRINT( "syscfg_set failed for eth_wan_iface_name\n" );
    }
    else
    {
        if ( syscfg_commit() != 0 )
        {
            GWPROV_PRINT( "syscfg_commit failed for eth_wan_iface_name\n" );
        }

    }
#endif

    validate_mode(&bridge_mode);
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", sysevent_bridge_mode);
    snprintf(BridgeMode, sizeof(BridgeMode), "%d", sysevent_bridge_mode);
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "bridge_mode", BridgeMode, 0);

    return 0;
}

static void LAN_start(void)
{
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);

#if defined (_PROPOSED_BUG_FIX_)
    // LAN Start May Be Delayed so refresh modes.
    GWPROV_PRINT("The Previous EROUTERMODE=%d\n",eRouterMode);
    GWPROV_PRINT("The Previous BRIDGE MODE=%d\n",bridge_mode);
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    GWPROV_PRINT("The Refreshed EROUTERMODE=%d\n",eRouterMode);
    GWPROV_PRINT("The Refreshed BRIDGE MODE=%d\n",bridge_mode);
#endif

    if (bridge_mode == 0 && eRouterMode != 0) // mipieper - add erouter check for pseudo bridge. Can remove if bridge_mode is forced in response to erouter_mode.
    {
        printf("Utopia starting lan...\n");
        GWPROV_PRINT(" Setting lan-start event \n");           
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "lan-start", "", 0);
        
        
    } else {
        // TODO: fix this
        printf("Utopia starting bridge...\n");
        GWPROV_PRINT(" Setting bridge-start event \n");         
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "bridge-start", "", 0);
    }
    
#ifdef DSLITE_FEATURE_SUPPORT
    {
        char buf[2];

        if ((syscfg_get(NULL, "4_to_6_enabled", buf, sizeof(buf)) == 0) && (strcmp(buf, "1") == 0))
        {
            GWPROV_PRINT("Setting dslite_enabled event\n");
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "dslite_enabled", "1", 0);
        }
    }
#endif

    //ADD MORE LAN NETWORKS HERE
    GWPROV_PRINT(" Setting dhcp_server-resync event \n");     
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "dhcp_server-resync", "", 0);
   
   return;
}

static void _get_shell_output (FILE *fp, char *buf, int len)
{
    if (fp == NULL)
    {
        *buf = 0;
        return;
    }

    buf = fgets (buf, len, fp);

    v_secure_pclose (fp); 

    if (buf != NULL)
    {
        len = strlen (buf);

        if ((len > 0) && (buf[len - 1] == '\n'))
        {
            buf[len - 1] = 0;
        }
    }
}

pid_t findProcessId(char* processName)
{

    FILE *f = NULL;
      pid_t pid = -1;

    char request[256], response[256];

    snprintf(request, sizeof(request), "ps  | grep %s", processName);

    if ((f = popen(request, "r")) != NULL)
    {
        fgets(response, (255), f);

        pclose(f);
    }

    snprintf(request,sizeof(request), "pidof %s", processName);

    if ((f = popen(request, "r")) != NULL)
    {
        fgets(response, (255), f);
        pid = atoi(response);
        pclose(f);
    }

    return pid;
}
/**************************************************************************/
/*! \fn int main(int argc, char *argv)
 **************************************************************************
 *  \brief Init and run the Provisioning process
 *  \param[in] argc
 *  \param[in] argv
 *  \return Currently, never exits
 **************************************************************************/
int main(int argc, char *argv[])
{
   printf("Started gw_prov_utopia\n");

    t2_init("ccsp-gwprovapp");


    #ifdef FEATURE_SUPPORT_RDKLOG
       setenv("LOG4C_RCPATH","/rdklogger",1);
       rdk_logger_init(DEBUG_INI_NAME);
    #endif

#ifndef _WNXL11BWL_PRODUCT_REQ_
    GWPROV_PRINT(" Entry gw_prov_utopia\n");
    GWPROV_PRINT(" Calling /etc/utopia/utopia_init.sh \n");
    v_secure_system("/etc/utopia/utopia_init.sh");
#endif

    GWP_act_ProvEntry();
    GWPROV_PRINT("wait in loop \n");
	while (1)
	{
		sleep(1);
	}

    if( findProcessId(argv[0]) > 0 )
    {
        printf("Already running\n");
        GWPROV_PRINT(" gw_prov_utopia already running. Returning...\n");
        return 1;
    }
   

    return 0;

}

