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
#include "gw_prov_abstraction.h"
#include "Tr69_Tlv.h"
#include <autoconf.h>
#ifdef AUTOWAN_ENABLE
#include "autowan.h"
#include "gw_prov_sm.h"
#endif
#if !defined(_PLATFORM_RASPBERRYPI_)
#include "docsis_esafe_db.h"
#endif
#include <time.h>
#include "secure_wrapper.h"
#ifdef FEATURE_SUPPORT_RDKLOG
#include "rdk_debug.h"
#endif


#include <telemetry_busmessage_sender.h>
#include "safec_lib_common.h"

#if defined(_XB6_PRODUCT_REQ_) || defined(_CBR2_PRODUCT_REQ_)
#include "platform_hal.h"
#endif
//Added for lxcserver thread function
#if defined(_PLATFORM_RASPBERRYPI_)
#define PORT 8081
#endif

/* Global Variables*/
#if !defined(AUTOWAN_ENABLE)
char log_buff[1024];
#endif
#define WHITE	0
#define RED	3
#define SOLID	0
#define BLINK	1

/**************************************************************************/
/*      DEFINES:                                                          */
/**************************************************************************/

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

#if !defined(AUTOWAN_ENABLE)
#ifdef FEATURE_SUPPORT_RDKLOG
#define GWPROV_PRINT(fmt ...)    {\
				    				snprintf(log_buff, 1023, fmt);\
                                    RDK_LOG(LOG_INFO, COMP_NAME, "%s", log_buff);\
                                 }
#else
#define GWPROV_PRINT printf
#endif
#endif

#if defined(AUTOWAN_ENABLE) && defined(INTEL_PUMA7)
#define ETHWAN_FILE     "/nvram/ETHWAN_ENABLE"
#endif

void _get_shell_output(FILE *fp, char * buf, int len);

static Tr69TlvData *tlvObject=NULL;
static int objFlag = 1;

typedef struct _GwTlv2ChangeFlags
{
    char EnableCWMP_modified;
    char URL_modified;
    char Username_modified;
    char Password_modified;
    char ConnectionRequestUsername_modified;
    char ConnectionRequestPassword_modified;
    char AcsOverride_modified;
}GwTlv2ChangeFlags_t;

/*Structure of local internal data */
typedef struct _GwTlvsLocalDB
{
    GwTlv2StructExtIf_t tlv2;
    GwTlv2ChangeFlags_t tlv2_flags;
}GwTlvsLocalDB_t;

/* New implementation !*/

#ifdef MULTILAN_FEATURE
#define BRG_INST_SIZE 5
#define BUF_SIZE 256
#endif

#if defined(INTEL_PUMA7)
extern CLIENT* Cgm_GatewayApiProxy_Init(void);
#endif
int sendPseudoBridgeModeMessage(unsigned char enable);

typedef enum {
    EROUTER_MODE,
    IPV4STATUS,
    IPV6STATUS,
    SYSTEM_RESTART,
    BRING_LAN,
    PNM_STATUS,
    PING_STATUS,
    SNMP_SUBAGENT_STATUS,
    PRIMARY_LAN_13NET,
    LAN_STATUS,
    BRIDGE_STATUS,
    DHCPV6_CLIENT_V6ADDR,
    WAN_STATUS,
    IPV6_PREFIX,
    CURRENT_WAN_IPADDR,
    IPV6_DHCP6_ADDR,
    CONN_STATUS,
    GWP_THREAD_ERROR
} eGwpThreadType;

typedef struct
{
    char         *msgStr; 
    eGwpThreadType mType;       
} GwpThread_MsgItem;

GwpThread_MsgItem gwpthreadMsgArr[] = {
    {"erouter_mode",                               EROUTER_MODE},
    {"ipv4-status",                                IPV4STATUS},
    {"ipv6-status",                                IPV6STATUS},
    {"system-restart",                             SYSTEM_RESTART},
    {"bring-lan",                                  BRING_LAN},
    {"pnm-status",                                 PNM_STATUS},
    {"ping-status",                                PING_STATUS},
    {"snmp_subagent-status",                       SNMP_SUBAGENT_STATUS},
    {"primary_lan_l3net",                          PRIMARY_LAN_13NET},
    {"lan-status",                                 LAN_STATUS},
    {"bridge-status",                              BRIDGE_STATUS},
    {"tr_" ER_NETDEVNAME "_dhcpv6_client_v6addr",  DHCPV6_CLIENT_V6ADDR},
    {"wan-status",                                 WAN_STATUS},
    {"ipv6_prefix",                                IPV6_PREFIX},
    {"current_wan_ipaddr",                         CURRENT_WAN_IPADDR},
    {"ipv6_dhcp6_addr",                            IPV6_DHCP6_ADDR},
    {"conn-status",                                CONN_STATUS},

};

/**************************************************************************/
/*      LOCAL DECLARATIONS:                                               */
/**************************************************************************/

/*! New implementation */
#if 0
static void GW_Local_PrintHexStringToStderr(Uint8 *str, Uint16 len);
static STATUS GW_TlvParserInit(void);
#endif
//static TlvParseCallbackStatus_e GW_SetTr069PaCfg(Uint8 type, Uint16 length, const Uint8* value);
static TlvParseCallbackStatusExtIf_e GW_Tr069PaSubTLVParse(Uint8 type, Uint16 length, const Uint8* value);
#if defined (_COSA_BCM_MIPS_) || defined(_COSA_BCM_ARM_)
static STATUS GW_UpdateTr069Cfg(void);
static STATUS GW_SetTr069PaDataInTLV11Buffer(Uint8* buf, Int* len);
static bool GW_SetTr069PaMibBoolean(Uint8 **cur, Uint8 sub_oid, Uint8 value);
static bool GW_SetTr069PaMibString(Uint8 **cur, Uint8 sub_oid, Uint8* value);
#endif
static void check_lan_wan_ready();
//static TlvParseCallbackStatus_e gotEnableType(Uint8 type, Uint16 length, const Uint8* value);

#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
static TlvParseCallbackStatusExtIf_e GW_setTopologyMode(Uint8 type, Uint16 length, const Uint8* value);
#endif

/* New implementation !*/
static void LAN_start();

static void *GWP_UpdateTr069CfgThread( void *data );

void GWP_Util_get_shell_output( char * cmd, char *out, int len );

void setGWP_ipv4_event();

void setGWP_ipv6_event();

int COMMONUTILS_file_write(const char *string, char* cmdline, int len);

STATUS GWP_InitDB(void);

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/


static int snmp_inited = 0;
static int pnm_inited = 0;
static int netids_inited = 0;
static int gDocTftpOk = 0;
static int hotspot_started = 0;
static int lan_telnet_started = 0;

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int ciscoconnect_started = 0;
#endif

static int webui_started = 0;
static Uint32 factory_mode = 0;
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
static int phylink_wan_state = 0;
static int once = 0;
static int bridge_mode = BRMODE_ROUTER;
static int active_mode = BRMODE_ROUTER;

static GwTlvsLocalDB_t gwTlvsLocalDB;

#if defined (INTEL_PUMA7)
//Intel Proposed RDKB Generic Bug Fix from XB6 SDK
static int sIPv4_acquired = 0;
static int sIPv6_acquired = 0;
#endif

/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
static void GWP_EnterBridgeMode(void);
static void GWP_EnterRouterMode(void);

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


#if !defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn STATUS GW_TlvParserInit(void)
 **************************************************************************
 *  \brief Initialize before the parsing
 *  \return Initialization status: OK/NOK
 **************************************************************************/
#if 0
static STATUS GW_TlvParserInit(void)
{
    errno_t rc = -1;
    /*Initialize local DB*/
    // GW_FreeTranstAddrAccessList();
    rc =  memset_s(&gwTlvsLocalDB,sizeof(gwTlvsLocalDB), 0, sizeof(gwTlvsLocalDB));
    ERR_CHK(rc);

    /*Open the SNMP response socket*/
    // GW_CreateSnmpResponseSocket();
    /*Init SNMP TLV's default values*/
    // GW_InitSNMPTlvsDefaults();

    return STATUS_OK;
}

static void GW_Local_PrintHexStringToStderr(Uint8 *str, Uint16 len)
 {
    int i; 

    fprintf(stderr, "hex string = '");
    for(i=0; i<len; i++) 
    {
        fprintf(stderr, "%02X", str[i]);
    }
    fprintf(stderr, "'\n");
 }
#endif

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

static bool WriteTr69TlvData(Uint8 typeOfTLV)
{
	int ret;
	errno_t rc = -1;
	GWPROV_PRINT(" Entry %s : typeOfTLV %d \n", __FUNCTION__, typeOfTLV);
	
	if (objFlag == 1)
	{
		tlvObject=malloc(sizeof(Tr69TlvData));
		if(tlvObject == NULL)
		{
			return FALSE;
		}
        rc =  memset_s(tlvObject,sizeof(Tr69TlvData), 0, sizeof(Tr69TlvData));
        ERR_CHK(rc);
		objFlag = 0;
	}
	/* Check if its a fresh boot-up or a boot-up after factory reset*/
	ret = IsFileExists(TR69_TLVDATA_FILE);

	if(ret == 0)
	{
		/* Need to create default values during fresh boot-up case*/
		tlvObject->FreshBootUp = TRUE;
		tlvObject->Tr69Enable = FALSE;
		FILE * file= fopen(TR69_TLVDATA_FILE, "wb");
		if (file != NULL)
		{
			fwrite(tlvObject, sizeof(Tr69TlvData), 1, file);
			fclose(file);

		}
	}
	FILE * file= fopen(TR69_TLVDATA_FILE, "rb");
	if (file != NULL)
	{
                /* Coverity Fix:CID 62659 CHECKED_RETURN  */
		if( fread(tlvObject, sizeof(Tr69TlvData), 1, file) < 1 )
	               GWPROV_PRINT(" Error in fread  %s \n", __FUNCTION__);
                    
		fclose(file);
	}
	else
	{
		printf("TLV data file can't be opened \n");
		GWPROV_PRINT(" TLV data file can't be opened \n");
		return FALSE;
	}

	if(tlvObject->FreshBootUp == TRUE)
	{
		GWPROV_PRINT(" Fresh Bootup \n");
		switch (typeOfTLV)
		{
            case GW_SUBTLV_TR069_ENABLE_CWMP_EXTIF:
                tlvObject->EnableCWMP = gwTlvsLocalDB.tlv2.EnableCWMP;
                break;
            case GW_SUBTLV_TR069_URL_EXTIF:
                rc =  memset_s(tlvObject->URL,sizeof(tlvObject->URL), 0, sizeof(tlvObject->URL));
                ERR_CHK(rc);
                rc = strcpy_s(tlvObject->URL,sizeof(tlvObject->URL),gwTlvsLocalDB.tlv2.URL);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return FALSE;
                }
                break;
            case GW_SUBTLV_TR069_USERNAME_EXTIF:
            case GW_SUBTLV_TR069_PASSWORD_EXTIF:
            case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
            case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
                break;
            case GW_SUBTLV_TR069_ACS_OVERRIDE_EXTIF:
                tlvObject->AcsOverRide = gwTlvsLocalDB.tlv2.ACSOverride;
                break;
            default:
                //(DUPLICATE)GWPROV_PRINTOut("TLV : %d can't be saved to TLV data file\n",typeOfTLV);
                GWPROV_PRINT(" TLV : %d can't be saved to TLV data file\n",typeOfTLV);
                break;
		}
	
	}
	else
	{
		/*In case of Normal bootup*/
		GWPROV_PRINT(" Normal Bootup \n");
		tlvObject->FreshBootUp = FALSE;
		switch (typeOfTLV)
		{
            case GW_SUBTLV_TR069_ENABLE_CWMP_EXTIF:
                tlvObject->EnableCWMP = gwTlvsLocalDB.tlv2.EnableCWMP;
                break;
            case GW_SUBTLV_TR069_URL_EXTIF:
                if(tlvObject->Tr69Enable == FALSE)
                {
                    // This is to make sure that we always use boot config supplied URL
                    // during TR69 initialization
                    rc =  memset_s(tlvObject->URL,sizeof(tlvObject->URL), 0, sizeof(tlvObject->URL));
                    ERR_CHK(rc);
                    rc = strcpy_s(tlvObject->URL,sizeof(tlvObject->URL),gwTlvsLocalDB.tlv2.URL);
                    if(rc != EOK)
                    {
                        ERR_CHK(rc);
                        return FALSE;
                    }
                }
                break;
            case GW_SUBTLV_TR069_USERNAME_EXTIF:
            case GW_SUBTLV_TR069_PASSWORD_EXTIF:
            case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
            case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
                break;
            case GW_SUBTLV_TR069_ACS_OVERRIDE_EXTIF:
                tlvObject->AcsOverRide = gwTlvsLocalDB.tlv2.ACSOverride;
                break;
            default:
                //(DUPLICATE)GWPROV_PRINTOut("TLV : %d can't be saved to TLV data file\n",typeOfTLV);
                GWPROV_PRINT(" TLV : %d can't be saved to TLV data file\n",typeOfTLV);
                break;
		}
	}

	file= fopen(TR69_TLVDATA_FILE, "wb");
	if (file != NULL)
	{
		fseek(file, 0, SEEK_SET);
		fwrite(tlvObject, sizeof(Tr69TlvData), 1, file);
		fclose(file);
	}
	
return TRUE;
}

static TlvParseCallbackStatusExtIf_e GW_Tr069PaSubTLVParse(Uint8 type, Uint16 length, const Uint8* value)
{
    errno_t rc = -1;
    GWPROV_PRINT(" %s : type %d, length %d , value %d\n", __FUNCTION__, type, length,*value);
    switch(type)
    {
        case GW_SUBTLV_TR069_ENABLE_CWMP_EXTIF:
            if ((int)(*value) == 0 || (int)(*value) == 1) {
                gwTlvsLocalDB.tlv2.EnableCWMP = (GwTr069PaEnableCwmpTypeExtIf_e)(*value);
                gwTlvsLocalDB.tlv2_flags.EnableCWMP_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.EnableCWMP = GW_TR069_ENABLE_CWMP_FALSE_EXTIF;
            break;

        case GW_SUBTLV_TR069_URL_EXTIF:
            if (length <= GW_TR069_TLV_MAX_URL_LEN) 
            {
		rc = memcpy_s(gwTlvsLocalDB.tlv2.URL, sizeof(gwTlvsLocalDB.tlv2.URL), value, length);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
                }
                gwTlvsLocalDB.tlv2.URL[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.URL_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.URL[0] = '\0';
            break;

        case GW_SUBTLV_TR069_USERNAME_EXTIF:
            if (length <= GW_TR069_TLV_MAX_USERNAME_LEN) 
            {
                rc = memcpy_s(gwTlvsLocalDB.tlv2.Username, sizeof(gwTlvsLocalDB.tlv2.Username), value, length);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
                }
                gwTlvsLocalDB.tlv2.Username[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.Username_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.Username[0] = '\0';
            break;

        case GW_SUBTLV_TR069_PASSWORD_EXTIF:
            if (length <= GW_TR069_TLV_MAX_PASSWORD_LEN) 
            {
                rc = memcpy_s(gwTlvsLocalDB.tlv2.Password, sizeof(gwTlvsLocalDB.tlv2.Password), value, length);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
                }
                gwTlvsLocalDB.tlv2.Password[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.Password_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.Password[0] = '\0'; 
            break;

        case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
            if (length <= GW_TR069_TLV_MAX_USERNAME_LEN) 
            {
                rc = memcpy_s(gwTlvsLocalDB.tlv2.ConnectionRequestUsername, sizeof(gwTlvsLocalDB.tlv2.ConnectionRequestUsername), value, length);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
                }
                gwTlvsLocalDB.tlv2.ConnectionRequestUsername[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.ConnectionRequestUsername_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.ConnectionRequestUsername[0] = '\0';
            break;

        case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
            if (length <= GW_TR069_TLV_MAX_PASSWORD_LEN) 
            {
                rc = memcpy_s(gwTlvsLocalDB.tlv2.ConnectionRequestPassword, sizeof(gwTlvsLocalDB.tlv2.ConnectionRequestPassword), value, length);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
                }
                gwTlvsLocalDB.tlv2.ConnectionRequestPassword[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.ConnectionRequestPassword_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.ConnectionRequestPassword[0] = '\0';
            break;

        case GW_SUBTLV_TR069_ACS_OVERRIDE_EXTIF:
            if ((int)(*value) == 0 || (int)(*value) == 1) {
                gwTlvsLocalDB.tlv2.ACSOverride = (GwTr069PaAcsOverrideTypeExtIf_e)(*value);
                gwTlvsLocalDB.tlv2_flags.AcsOverride_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.ACSOverride = GW_TR069_ACS_OVERRIDE_DISABLED_EXTIF;
            break;

        default:
            printf("Unknown Sub TLV In TLV 2\n");
            break;
    }
			
    if(WriteTr69TlvData(type))
	{		
        return TLV_PARSE_CALLBACK_OK_EXTIF;
	}
	else
	{
	    return TLV_PARSE_CALLBACK_ABORT_EXTIF;
	}
}

// All MIB entries in hex are: 30 total_len oid_base oid_value 00 data_type data_len data

// Oid_Base = 1.3.6.1.4.1.1429.79.6.1
#if defined (_COSA_BCM_MIPS_) || defined(_COSA_BCM_ARM_)
static Uint8 GW_Tr069PaMibOidBase[12] = { 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8b, 0x15, 0x4f, 0x06, 0x01 }; 
#endif

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

#if defined (_COSA_BCM_MIPS_) || defined(_COSA_BCM_ARM_)
static bool GW_SetTr069PaMibBoolean(Uint8 **cur, Uint8 sub_oid, Uint8 value)
{
    Uint8 *mark;
    Uint8 *current = *cur;
    errno_t rc = -1;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    // SEQUENCE (0x30); Skip total length (1-byte, to be filled later)
    *(current++) = 0x30; current++; mark = current; 
    rc = memcpy_s(current, SNMP_DATA_BUF_SIZE, GW_Tr069PaMibOidBase, sizeof(GW_Tr069PaMibOidBase));
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    current += 12;  
    *(current++) = sub_oid;
    *(current++) = GW_TR069_MIB_SUB_OID_INSTANCE_NUM;
    *(current++) = GW_TR069_MIB_DATATYPE_BOOL; 
    *(current++) = GW_TR069_MIB_DATATYPE_LEN_BOOL;
    *(current++) = value;
    *(mark-1) = (Uint8)(current - mark);

    *cur = current;
	return TRUE;
}

static bool GW_SetTr069PaMibString(Uint8 **cur, Uint8 sub_oid, Uint8* value)
{
    Uint8 *mark;
    Uint8 *current = *cur;
    errno_t rc = -1;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    // SEQUENCE (0x30); Skip total length (1-byte, to be filled later)
    *(current++) = 0x30; current++; mark = current; 
    rc = memcpy_s(current, SNMP_DATA_BUF_SIZE, GW_Tr069PaMibOidBase, sizeof(GW_Tr069PaMibOidBase));
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    current += 12;  
    *(current++) = sub_oid;
    *(current++) = GW_TR069_MIB_SUB_OID_INSTANCE_NUM;
    *(current++) = GW_TR069_MIB_DATATYPE_STRING; 
    *(current++) = (Uint8)strlen(value);
    if(*(current-1))
    {
        rc = memcpy_s(current, SNMP_DATA_BUF_SIZE, value, *(current-1));
        if(rc != EOK)
        {
           ERR_CHK(rc);
           return FALSE;
        }
        current += *(current-1);
    }
    *(mark-1) = (Uint8)(current - mark);

    *cur = current;
	return TRUE;
}

static STATUS GW_SetTr069PaDataInTLV11Buffer(Uint8* buf, Int* len)
{
    Uint8 *ptr = buf;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    // EnableCWMP
    if(gwTlvsLocalDB.tlv2_flags.EnableCWMP_modified){
        if(!GW_SetTr069PaMibBoolean(&ptr, GW_TR069_MIB_SUB_OID_ENABLE_CWMP, (Uint8)(gwTlvsLocalDB.tlv2.EnableCWMP)))
		{
			return STATUS_NOK;
		}
	}
    // URL
    if(gwTlvsLocalDB.tlv2_flags.URL_modified){
        if(!GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_URL, (Uint8*)(gwTlvsLocalDB.tlv2.URL)))
		{
		     return STATUS_NOK;	
		}
    }
    // Username
    if(gwTlvsLocalDB.tlv2_flags.Username_modified){
        if(!GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_USERNAME, (Uint8*)(gwTlvsLocalDB.tlv2.Username)))
		{
		   return STATUS_NOK;	
		}
	}

    // Password
    if(gwTlvsLocalDB.tlv2_flags.Password_modified){
        if(!GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_PASSWORD, (Uint8*)(gwTlvsLocalDB.tlv2.Password)))
		{
			return STATUS_NOK;
		}
	}
    // ConnectionRequestUsername
    if(gwTlvsLocalDB.tlv2_flags.ConnectionRequestUsername_modified){
        if(!GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_CONNREQ_USERNAME, (Uint8*)(gwTlvsLocalDB.tlv2.ConnectionRequestUsername)))
		{
			return STATUS_NOK;
		}
	}

    // ConnectRequestPassword
    if(gwTlvsLocalDB.tlv2_flags.ConnectionRequestPassword_modified){
        if(!GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_CONNREQ_PASSWORD, (Uint8*)(gwTlvsLocalDB.tlv2.ConnectionRequestPassword)))
		{
		     return STATUS_NOK;	
		}
	}

    // ACSOverride
    if(gwTlvsLocalDB.tlv2_flags.AcsOverride_modified){
        if(!GW_SetTr069PaMibBoolean(&ptr, GW_TR069_MIB_SUB_OID_ALLOW_DOCSIS_CONFIG, (Uint8)(gwTlvsLocalDB.tlv2.ACSOverride)))
		{
			return STATUS_NOK;
		}
	}

    *len = ptr - buf;

    return STATUS_OK;
}

static STATUS GW_UpdateTr069Cfg(void)
{   
    /* SNMP TLV's data buffer*/
    Uint8 Snmp_Tlv11Buf[SNMP_DATA_BUF_SIZE] = {0};
    Int Snmp_Tlv11BufLen = 0;
    STATUS ret = STATUS_OK;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    /*Init the data buffer*/

    /*Convert TLV 202.2 data into TLV11 data*/
    ret = GW_SetTr069PaDataInTLV11Buffer(Snmp_Tlv11Buf, &Snmp_Tlv11BufLen);
        if (ret == STATUS_NOK)
	{
		return ret;
	}
	
    /*
    fprintf(stderr, "<RT> %s - Snmp \n", __FUNCTION__);
    GW_Local_PrintHexStringToStderr(Snmp_Tlv11Buf, Snmp_Tlv11BufLen);
    */

    
  
    /*Send TLV11 data to SNMP Agent*/
    if(Snmp_Tlv11BufLen)
    {
        ret = sendTLV11toSnmpAgent((void *)Snmp_Tlv11Buf, (int)Snmp_Tlv11BufLen );
        
    }

    return ret;
  
  

#if 0
        SnmpaIfResponse_t *tlv11Resp = (SnmpaIfResponse_t*)malloc(sizeof(SnmpaIfResponse_t)+sizeof(int));
        if (!tlv11Resp)
        {
            LOG_GW_ERROR("Failed to allocate dynamic memory");
            goto label_nok;
        }
        rc =  memset_s(tlv11Resp,sizeof(SnmpaIfResponse_t)+sizeof(int), 0, sizeof(SnmpaIfResponse_t)+sizeof(int));
        ERR_CHK(rc);
        /* Set TLV11 whitin whole config file and TLV11 duplication test */
        ret = (STATUS)SNMPAIF_SetTLV11Config(SNMP_AGENT_CTRL_SOCK, (void *)Snmp_Tlv11Buf, (int)Snmp_Tlv11BufLen, tlv11Resp);

        if(tlv11Resp->len >= sizeof(int))
        {
            Int32 errorCode = 0;

	    /*
             * Copy the error code
             */
	    errorCode = (int) *(tlv11Resp->value);

            /*Need to send the required event*/
            // ReportTlv11Events(errorCode);

            LOG_GW_ERROR("Failed to set TLV11 parameters - error code = %d", errorCode);
            // fprintf(stderr, "<RT> %s - Failed to set TLV11 parameters - error code = %d\n", __FUNCTION__, errorCode);
        }
   
        if(ret != STATUS_OK)
        {
#if (SA_CUSTOM)
            LOG_GW_ERROR("TLV11 internal SNMP set failed! IGNORING...");
#else //TI Org
            LOG_GW_ERROR("TLV11 internal SNMP set failed!");
            if(tlv11Resp) free(tlv11Resp);
            goto label_nok;
#endif
        }

        if(tlv11Resp) free(tlv11Resp);
    }

    return STATUS_OK;

label_nok:
    return STATUS_NOK;
#endif 
}
#endif
#endif

#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
static TlvParseCallbackStatusExtIf_e GW_setTopologyMode(Uint8 type, Uint16 length, const Uint8* value)
{
    Uint8 tpMode = *value;
    TlvParseCallbackStatusExtIf_e st = TLV_PARSE_CALLBACK_OK_EXTIF;

    printf("TLV %d, Len %d : Topology Mode\n", type, length);
    GWPROV_PRINT(" %s : type %d, length %d , tpMode %d\n", __FUNCTION__, type, length,tpMode);
    if ( (tpMode == TLV202_42_FAVOR_DEPTH) || (tpMode == TLV202_42_FAVOR_WIDTH))
    {
        printf("eSafe CFG file : Found Topology Mode, val %d\n", tpMode);
        v_secure_system("sysevent set erouter_topology-mode %d", tpMode);
    }
    else
    {
        printf("eSafe CFG file : Found Topology Mode, illegal val %d, use default value.\n", tpMode);
        st = TLV_PARSE_CALLBACK_ABORT_EXTIF;
    }

    return st;
}
#endif

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

/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgSetInt
 **************************************************************************
 *  \brief Set Syscfg Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
static int GWP_SysCfgSetInt(const char *name, int int_value)
{
   char value[20];

   sprintf(value, "%d", int_value);
   GWPROV_PRINT(" %s : name = %s , value = %s \n", __FUNCTION__, name, value);

   if ((strcmp(name, "last_erouter_mode") == 0) && (strcmp(value, "2") == 0))
   {
       t2_event_d("SYS_INFO_ERouter_Mode_2", 1);
   }

   return syscfg_set(NULL, name, value);
}

#if !defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn static STATUS GWP_UpdateEsafeAdminMode()
 **************************************************************************
 *  \brief Update esafeAdminMode
 *  \return OK/NOK
 **************************************************************************/
static STATUS GWP_UpdateEsafeAdminMode(DOCSIS_Esafe_Db_extIf_e enableMode)
{
    
    eSafeDevice_Enable(enableMode);

    return STATUS_OK;
}

/**************************************************************************/
/*! \fn Bool GWP_IsGwEnabled(void)
 **************************************************************************
 *  \brief Is gw enabled
 *  \return True/False
**************************************************************************/
static Bool GWP_IsGwEnabled(void)
{
    
    if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
    {
        return False;
    }
    else
    {
        return True;
    }
}
#endif

/* Coverity Fix CID:56406 MISSING_RETURN */
void 
validate_mode(int* bridge_mode, int* eRouterMode)
{
	if((*eRouterMode < DOCESAFE_ENABLE_DISABLE_extIf)  || (*eRouterMode > DOCESAFE_ENABLE_NUM_ENABLE_TYPES_extIf)
		|| ((*bridge_mode != BRMODE_ROUTER) && (*bridge_mode != BRMODE_PRIMARY_BRIDGE) && (*bridge_mode != BRMODE_GLOBAL_BRIDGE)))
	{
		GWPROV_PRINT(" SYSDB_CORRUPTION: bridge_mode = %d , eRouterMode = %d \n", *bridge_mode, *eRouterMode);
		GWPROV_PRINT(" SYSDB_CORRUPTION: Switching to Default Router Mode \n");
		*eRouterMode = DOCESAFE_ENABLE_IPv4_IPv6_extIf;
		*bridge_mode = BRMODE_ROUTER;

		GWP_SysCfgSetInt("last_erouter_mode", *eRouterMode);
		GWP_SysCfgSetInt("bridge_mode", *bridge_mode);
		if( syscfg_commit() != 0)
                      GWPROV_PRINT(" %s : syscfg_commit not success \n", __FUNCTION__);
                  
	}
	GWPROV_PRINT(" %s : bridge_mode = %d , eRouterMode = %d \n", __FUNCTION__, *bridge_mode, *eRouterMode);
 }

#if !defined(_PLATFORM_RASPBERRYPI_)
void docsis_gotEnable_callback(Uint8 state)
{
	GWPROV_PRINT(" Entry %s , state = %d \n", __FUNCTION__, state);
   eRouterMode = state;

}
/**************************************************************************/
/*! \fn void GWP_DocsisInited(void)
 **************************************************************************
 *  \brief Actions when DOCSIS is initialized
 *  \return None
**************************************************************************/
static void GWP_DocsisInited(void)
{
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    macaddr_t macAddr;
   
    /* Initialize docsis interface */
    initializeDocsisInterface();

    /* Register the eRouter  */
    getNetworkDeviceMacAddress(&macAddr);

#if defined (_PROPOSED_BUG_FIX_)
    GWPROV_PRINT("After calling getNetworkDeviceMacAddress MacAddr is \
                    [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                    macAddr.hw[0],macAddr.hw[1],
                    macAddr.hw[2],macAddr.hw[3],
                    macAddr.hw[4],macAddr.hw[5]);
#endif

    eSafeDevice_Initialize(&macAddr);
       
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_NOT_INITIATED_extIf);
	
     /* Add paths */
     
     eSafeDevice_AddeRouterPhysicalNetworkInterface(IFNAME_ETH_0, True);
           
     eSafeDevice_AddeRouterPhysicalNetworkInterface("usb0",True);

#if !defined(INTEL_PUMA7)
    /* Register on more events */
    registerDocsisEvents();
    
    if(factory_mode)
        LAN_start();
#endif

}

#endif

/**************************************************************************/
/*! \fn void GWP_EnableERouter(void)
 **************************************************************************
 *  \brief Actions enable eRouter
 *  \return None
**************************************************************************/
static void GWP_EnableERouter(void)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    /* Update ESAFE state */
    GWP_UpdateEsafeAdminMode(eRouterMode);

    eSafeDevice_SetErouterOperationMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6_extIf);
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_IN_PROGRESS_extIf);
	
#endif
    //bridge_mode = 0;
    //system("sysevent set bridge_mode 0");
    //system("sysevent set forwarding-restart");
	GWP_EnterRouterMode();
    v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string router");

    printf("******************************\n");
    printf("* Enabled (after cfg file)  *\n");
    printf("******************************\n");
}

//Actually enter router mode
static void GWP_EnterRouterMode(void)
{
         /* Coverity Issue Fix - CID:71381 : UnInitialised varible */
	char MocaPreviousStatus[16] = {0};
       	int prev;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
         return;
    //mipieper - removed for psuedo bridge.
//     GWP_UpdateEsafeAdminMode(eRouterMode);
//     DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6);
//     DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_IN_PROGRESS);

//    bridge_mode = 0;
        v_secure_system("sysevent set bridge_mode %d", BRMODE_ROUTER);
	syscfg_get(NULL, "MoCA_previous_status", MocaPreviousStatus, sizeof(MocaPreviousStatus));
	prev = atoi(MocaPreviousStatus);
	GWPROV_PRINT(" MocaPreviousStatus = %d \n", prev);
	if(prev == 1)
	{
		v_secure_system("dmcli eRT setv Device.MoCA.Interface.1.Enable bool true");
	}
	else
	{
		v_secure_system("dmcli eRT setv Device.MoCA.Interface.1.Enable bool false");
	}

    v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool true");
    
    v_secure_system("sysevent set forwarding-restart");
}

/**************************************************************************/
/*! \fn void GWP_DisableERouter(void)
 **************************************************************************
 *  \brief Actions disable eRouter
 *  \return None
**************************************************************************/
static void GWP_DisableERouter(void)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    /* Update ESAFE state */
    GWP_UpdateEsafeAdminMode(eRouterMode);

    eSafeDevice_SetErouterOperationMode(DOCESAFE_EROUTER_OPER_DISABLED_extIf);
    
    /* Reset Switch, to remove all VLANs */ 
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_NOT_INITIATED_extIf);
#endif
//    char sysevent_cmd[80];
//     snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", bridge_mode);
//     system(sysevent_cmd);
//     system("sysevent set forwarding-restart");
    
    
    GWP_EnterBridgeMode();
    v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string bridge-static");

    printf("******************************\n");
    printf("* Disabled (after cfg file)  *\n");
    printf("******************************\n");
}

static void GWP_EnterBridgeMode(void)
{
    //GWP_UpdateEsafeAdminMode(DOCESAFE_ENABLE_DISABLE);
    //DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_DISABLED);
    /* Reset Switch, to remove all VLANs */ 
    // GSWT_ResetSwitch();
    //DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_NOT_INITIATED);
	char MocaStatus[16]  = {0};
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
    v_secure_system("dmcli eRT setv Device.MoCA.Interface.1.Enable bool false");
    v_secure_system("sysevent set bridge_mode %d", active_mode);
    v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool false");
    
    v_secure_system("sysevent set forwarding-restart");
}

#if 0
static void GWP_EnterPseudoBridgeMode(void)
{
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
        if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
        return;
    
//     GWP_UpdateEsafeAdminMode(eRouterMode);
//     DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6);
//     DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_IN_PROGRESS);
	
char MocaStatus[16] = {0};

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
	
    v_secure_system("dmcli eRT setv Device.MoCA.Interface.1.Enable bool false");
    v_secure_system("sysevent set bridge_mode %d", BRMODE_PRIMARY_BRIDGE);
    v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool false");
    v_secure_system("sysevent set forwarding-restart");
}
#endif

/**************************************************************************/
/*! \fn void GWP_UpdateERouterMode(void)
 **************************************************************************
 *  \brief Actions when ERouter Mode is Changed
 *  \return None
**************************************************************************/
static void GWP_UpdateERouterMode(void)
{
    // This function is called when TLV202 is received with a valid Router Mode
    // It could trigger a mode switch but user can still override it...
    printf("%s: %d->%d\n", __func__, oldRouterMode, eRouterMode);
    GWPROV_PRINT(" %s: %d->%d\n", __func__, oldRouterMode, eRouterMode);
    if (oldRouterMode != eRouterMode)
    {
        

        
        if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
        {
            // This means we are switching from router mode to bridge mode, set bridge_mode
            // to 2 since user did not specify it
            bridge_mode = 2;
            webui_started = 0;
            active_mode = BRMODE_GLOBAL_BRIDGE; //This is set so that the callback from LanMode does not trigger another transition.
                                                //The code here will here will handle it.
#ifdef DSLITE_FEATURE_SUPPORT
	     /* Modified In bridge mode DSLite should not start*/
            /*Enter bridge mode, DSLite won't be triggered to start, so we need to clear the previous DSLite service buffered status*/
            v_secure_system("service_dslite clear &");
#endif
            v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string bridge-static");
            
            GWP_DisableERouter();
            
            GWP_SysCfgSetInt("last_erouter_mode", eRouterMode);  // save the new mode only
              if (syscfg_commit() != 0) 
                    printf("syscfg_commit  for new mode failed\n");
              
        }
        else
        {
            GWP_SysCfgSetInt("last_erouter_mode", eRouterMode);  // save the new mode only
             if (syscfg_commit() != 0) 
                    printf("syscfg_commit failed for DOCESAFE_ENABLE_DISABLE_extIf \n");
            // TLV202 allows eRouter, but we still need to check user's preference
            //bridge_mode = GWP_SysCfgGetInt("bridge_mode");
            //if (bridge_mode == 1 || bridge_mode == 2)
            //{
                // erouter disabled by user, keep it disabled
                //mipieper -- dont disable erouter on bridge mode 
                //eRouterMode = DOCESAFE_ENABLE_DISABLE;
            //}
#ifdef DSLITE_FEATURE_SUPPORT
            /* Modification to handle DSLite in IPV4 only mode */
            /*If enter IPv4 only mode, DSLite also won't be triggered to start, clear the previous DSLite service buffered status*/
            if(eRouterMode == DOCESAFE_ENABLE_IPv4_extIf)
            {
                v_secure_system("service_dslite clear &");
            }
#endif
            /*else*/ if (oldRouterMode == DOCESAFE_ENABLE_DISABLE_extIf) // from disable to enable
            {
                webui_started = 0;
                active_mode = BRMODE_ROUTER; //This is set so that the callback from LanMode does not trigger another transition.
                                                    //The code here will here will handle it.
                v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string router");
                GWP_EnableERouter();
            }
            else  // remain enabled, switch mode
            {
#if !defined(_PLATFORM_RASPBERRYPI_)
                /* Update ESAFE state */
                GWP_UpdateEsafeAdminMode(eRouterMode);
#endif
                if(!once)
                    check_lan_wan_ready();
                v_secure_system("sysevent set erouter_mode-updated");
            }
        }
    }
}

/**************************************************************************/
/*! \fn void GWP_ProcessUtopiaRestart(void)
 **************************************************************************
 *  \brief Actions when GUI request restarting of Utopia (bridge mode changes)
 *  \return None
**************************************************************************/
static void GWP_ProcessUtopiaRestart(void)
{
    // This function is called when "system-restart" event is received, This
    // happens when WEBUI change bridge configuration. We do not restart the
    // whole system, only routing/bridging functions only

    int oldActiveMode = active_mode;

    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    //int loc_eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    
    active_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);

    printf("bridge_mode = %d, erouter_mode = %d, active_mode = %d\n", bridge_mode, eRouterMode, active_mode);
    GWPROV_PRINT(" bridge_mode = %d, erouter_mode = %d, active_mode = %d\n", bridge_mode, eRouterMode, active_mode);

    if (oldActiveMode == active_mode) return; // Exit if no transition
    
    webui_started = 0;
    switch ( active_mode) 
	{
        case BRMODE_ROUTER:
            GWP_EnterRouterMode();
            break;

        case BRMODE_GLOBAL_BRIDGE:
        case BRMODE_PRIMARY_BRIDGE:
            GWP_EnterBridgeMode();
            break;
        default:
        break;
    }
    
    
//     if (eRouterMode == DOCESAFE_ENABLE_DISABLE) // TLV202 only allows bridge mode
//     {
//         //bridge_mode = 2;
//         //mipieper - removed for pseudo bridge mode support, as syscfg bridge_mode cannot
//     //cause a global bridge mode transition
//         //GWP_EnterBridgeMode();
//     }
//     else
//     {
//         webui_started = 0;
//         if (bridge_mode == 1 || bridge_mode == 2)
//         {
//             //loc_eRouterMode = DOCESAFE_ENABLE_DISABLE; // honor user's choice for bridge mode
//             GWP_EnterPseudoBridgeMode();
//         } else { 
//             GWP_EnterRouterMode();
//         }
//     }
}

#if !defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn int GWP_ProcessIpv4Down();
 **************************************************************************
 *  \brief IPv4 WAN Side Routing - Exit
 *  \return 0
**************************************************************************/
static int GWP_ProcessIpv4Down(void)
{
    esafeErouterOperModeExtIf_e operMode;

    /* Set operMode */
    
    eSafeDevice_GetErouterOperationMode(&operMode);
	GWPROV_PRINT(" operMode = %d \n", operMode);
    if (operMode == DOCESAFE_EROUTER_OPER_IPV4_IPV6_extIf)
    {
        /* Now we have both --> Go to v6 only */
        operMode = DOCESAFE_EROUTER_OPER_IPV6_extIf;
    }
    else
    {
        /* Only v4 --> Neither */
        operMode = DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6_extIf;
    }
    
    eSafeDevice_SetErouterOperationMode(operMode);

    return 0;
}

/**************************************************************************/
/*! \fn int GWP_ProcessIpv4Up
 **************************************************************************
 *  \brief IPv4 WAN Side Routing
 *  \return 0
**************************************************************************/
static int GWP_ProcessIpv4Up(void)
{
    esafeErouterOperModeExtIf_e operMode;

    /*update esafe db with router provisioning status*/
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_FINISHED_extIf);

    /* Set operMode */
    eSafeDevice_GetErouterOperationMode(&operMode);
	GWPROV_PRINT(" operMode = %d \n", operMode);
    if (operMode == DOCESAFE_EROUTER_OPER_IPV6_extIf)
    {
        /* Now we have both */
        operMode = DOCESAFE_EROUTER_OPER_IPV4_IPV6_extIf;
    }
    else
    {
        /* Only v4 */
        operMode = DOCESAFE_EROUTER_OPER_IPV4_extIf;
    }
    eSafeDevice_SetErouterOperationMode(operMode);

    printf("******************************\n");
    printf("*        IPv4 Routing        *\n");
    printf("******************************\n");

    return 0;
}

/**************************************************************************/
/*! \fn int GWP_ProcessIpV6Down()
 **************************************************************************
 *  \brief IPv6 WAN Side Routing - Exit
 *  \return 0
**************************************************************************/
static int GWP_ProcessIpv6Down(void)
{
    esafeErouterOperModeExtIf_e operMode;

    /* Set operMode */
    eSafeDevice_GetErouterOperationMode(&operMode);
	GWPROV_PRINT(" operMode = %d \n", operMode);
    if (operMode == DOCESAFE_EROUTER_OPER_IPV4_IPV6_extIf)
    {
        /* Now we have both --> Go to v4 only */
        operMode = DOCESAFE_EROUTER_OPER_IPV4_extIf;
    }
    else
    {
        /* Only v6 --> Neither */
        operMode = DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6_extIf;
    }
    
    eSafeDevice_SetErouterOperationMode(operMode);

    return 0;
}

/**************************************************************************/
/*! \fn int GWP_ProcessIpV6Up()
 **************************************************************************
 *  \brief IPv6 WAN Side Routing
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_ProcessIpv6Up(void)
{
    esafeErouterOperModeExtIf_e operMode;

    /*update esafe db with router provisioning status*/
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_FINISHED_extIf);
    

    /* Set operMode */
    eSafeDevice_GetErouterOperationMode(&operMode);
	GWPROV_PRINT(" operMode = %d \n", operMode);
    if (operMode == DOCESAFE_EROUTER_OPER_IPV4_extIf)
    {
        /* Now we have both */
        operMode = DOCESAFE_EROUTER_OPER_IPV4_IPV6_extIf;
        
    }
    else
    {
        /* Only v6 */
        operMode = DOCESAFE_EROUTER_OPER_IPV6_extIf;
    }
    eSafeDevice_SetErouterOperationMode(operMode);


    printf("******************************\n");
    printf("*        IPv6 Routing        *\n");
    printf("******************************\n");

    return 0;
}
#endif

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
#if defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn void *GWP_lxcserver_threadfunc(void *data)
 **************************************************************************
 *  \brief Function to process lxc based sysevent from other ccsp component 
 *  \return 0
**************************************************************************/
static void *GWP_lxcserver_threadfunc(void *data)
{
//lxc server to to listen for pandm client 
    int lxcsock_fd, lxcconn_fd, readbytes;
    struct sockaddr_in lxcsock_addr;
    int lxcsock_opt = 1;
    int addrlen = sizeof(lxcsock_addr);
    char buffer[1024] = {0};
    char *token = NULL;
    if((lxcsock_fd = socket(AF_INET, SOCK_STREAM, 0))==0)
    {
        perror("lxc server socket creation failed");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(lxcsock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &lxcsock_opt, sizeof(lxcsock_opt)))
    {
        perror("lxc server set socket option failed");
        exit(EXIT_FAILURE);
    }
    lxcsock_addr.sin_family = AF_INET;
    lxcsock_addr.sin_addr.s_addr = INADDR_ANY;
    lxcsock_addr.sin_port = htons( PORT );
    if (bind(lxcsock_fd, (struct sockaddr *)&lxcsock_addr, sizeof(lxcsock_addr))<0)
    {
        perror("lxc server bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(lxcsock_fd, 3) < 0)
    {
        perror("lxc server listen failed");
        exit(EXIT_FAILURE);
    }
    // To keep listening for client (pandm) connection
    while(1)
    {
        if ((lxcconn_fd = accept(lxcsock_fd, (struct sockaddr *)&lxcsock_addr, (socklen_t*)&addrlen))<0)
        {
            perror("lxc server accept failed");
            exit(EXIT_FAILURE);
        }
       else
           break;
    }
    // To keep listening for sys event message from pandm client
    while(1)
    {
        readbytes = recv( lxcconn_fd , buffer, 1024,0);
        printf("%s\n",buffer );
        v_secure_system(buffer);
    }
    close(lxcsock_fd); //Close the lxc server socket
    return 0;
}
#endif
/**************************************************************************/
/*! \fn void *GWP_sysevent_threadfunc(void *data)
 **************************************************************************
 *  \brief Function to process sysevent event
 *  \return 0
**************************************************************************/
static void *GWP_sysevent_threadfunc(void *data)
{
    async_id_t erouter_mode_asyncid;
    async_id_t ipv4_status_asyncid;
    async_id_t ipv6_status_asyncid;
    async_id_t system_restart_asyncid;
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

#if defined (INTEL_PUMA7)
    //Intel Proposed RDKB Generic Bug Fix from XB6 SDK	
    async_id_t wan_ipaddr_asyncid;
    async_id_t dhcp6_addr_asyncid;
#endif

    // char buf[10];
    time_t time_now = { 0 }, time_before = { 0 };
    // errno_t rc = -1;
    // int ind = -1;        
    
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__); 
    sysevent_setnotification(sysevent_fd, sysevent_token, "erouter_mode", &erouter_mode_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv4-status",  &ipv4_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6-status",  &ipv6_status_asyncid);
    sysevent_setnotification(sysevent_fd, sysevent_token, "system-restart",  &system_restart_asyncid);
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
#if defined (INTEL_PUMA7)
    //Intel Proposed RDKB Generic Bug Fix from XB6 SDK		
    /* Registering to get notification for IPv4 address assigned to erouter */
    sysevent_setnotification(sysevent_fd, sysevent_token, "current_wan_ipaddr",  &wan_ipaddr_asyncid);
    /* Registering to get notification for IPv6 address assigned to erouter */
    sysevent_setnotification(sysevent_fd, sysevent_token, "ipv6_dhcp6_addr",  &dhcp6_addr_asyncid);
#endif

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
        char name[25], val[42], buf[BUF_SIZE];
#else
        char name[25], val[42];
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
        char responseCode[10]={0}, cp_enable[10]={0}, redirect_flag[10]={0};
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
            ret_value = Get_GwpThreadType(name);            
            if (ret_value == EROUTER_MODE)
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

                GWP_UpdateERouterMode();
                sleep(5);
                v_secure_system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Device"); // Reboot on change of device mode and backup logs.
            }
            else if (ret_value == IPV4STATUS)
            {
                rc = strcmp_s("up", strlen("up"),val, &ind);
                ERR_CHK(rc);
                if ((ind == 0) && (rc == EOK))
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv4Up();
#endif
                }
                else 
                {
                    rc = strcmp_s("down", strlen("down"),val, &ind);
                    ERR_CHK(rc);
                    if ((ind == 0) && (rc == EOK))
                    {
#if !defined(_PLATFORM_RASPBERRYPI_)
                         GWP_ProcessIpv4Down();
#endif
                    }
                }
            }
            else if (ret_value == IPV6STATUS)
            {
                rc = strcmp_s("up", strlen("up"),val, &ind);
                ERR_CHK(rc);
                if ((ind == 0) && (rc == EOK))
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv6Up();
#endif
                }
                else 
                {
                    rc = strcmp_s("down", strlen("down"),val, &ind);
                    ERR_CHK(rc);
                    if ((ind == 0) && (rc == EOK))
                    {
#if !defined(_PLATFORM_RASPBERRYPI_)
                        GWP_ProcessIpv6Down();
#endif
                     }
                }
            }
            else if (ret_value == SYSTEM_RESTART)
            {
                printf("gw_prov_sm: got system restart\n");
                GWP_ProcessUtopiaRestart();
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
                   // Set LED state based on whether device is in CP or not
	
		    ledMgmt.LedColor = WHITE;

		    ledMgmt.State  = SOLID;
		    ledMgmt.Interval = 0;
		    
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
						char buf[256] = {0};
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
                Uint8 v6addr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ] = {0};
                /* Coverity Issue Fix - CID:79291 : UnInitialised varible  */
                Uint8 soladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ] = {0} ;
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
			}
			else if (ret_value == IPV6_PREFIX && strlen(val) > 5) {
				if (!once) {
						check_lan_wan_ready();
					}
			}
#if defined (INTEL_PUMA7)
			//Intel Proposed RDKB Generic Bug Fix from XB6 SDK
			else if (ret_value == CURRENT_WAN_IPADDR)
            {
                /* Set the "ipv4-status" to "up" when there is an IPv4 address assigned to gateway WAN interface */
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv4-status", "up", 0);
                if (!sIPv4_acquired && val )
                {
                    rc = strcmp_s("0.0.0.0", strlen("0.0.0.0"),val, &ind);
                    ERR_CHK(rc);
                    if ((ind != 0) && (rc == EOK)){
                       setGWP_ipv4_event();
                       sIPv4_acquired = 1; /* Setting it here, to send IPv4 event only once. Ignore any further RENEW messages */
                    }
                }
            }
            else if (ret_value == IPV6_DHCP6_ADDR)
            {
                /* Set the "ipv6-status" to "up" when there is an IPv6 address assigned to gateway WAN interface */
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv6-status", "up", 0);
				if (!sIPv6_acquired && val)
                {
                    setGWP_ipv6_event();
                    sIPv6_acquired = 1; /* Setting it here, to send IPv6 event only once. Ignore any further RENEW/REBIND messages*/
                }
            }
#endif
        }
    }
    return 0;
}




/**************************************************************************/
/*! \fn int GWP_act_DocsisLinkDown(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions required upon linkDown from ActiveProvisioned
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_act_DocsisLinkDown_callback_1()
{
    phylink_wan_state = 0;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "phylink_wan_state", "down", 0);
   
    printf("\n**************************\n");
    printf("\nsysevent set phylink_wan_state down\n");
    printf("\n**************************\n\n");
    return 0;
}

static int GWP_act_DocsisLinkDown_callback_2()
{
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf)
    {
#ifdef DSLITE_FEATURE_SUPPORT
       if(eRouterMode == DOCESAFE_ENABLE_IPv6_extIf || eRouterMode == DOCESAFE_ENABLE_IPv4_IPv6_extIf)
       {
           /*Need to clear the value of erouter0 IPv6 address event,
           otherwise the sysevent tr_erouter0_dhcpv6_client_v6addr won't
           be triggered if the erouter0 get the same IPv6 address when link up.
           The DSLite also need to be stopped when link down, and will be started when link up*/
           v_secure_system("sysevent set tr_erouter0_dhcpv6_client_v6addr");
           /*Clear the IPv6 rules that maybe block the DHCPv6 response when link up, those rules will
           be updated once erouter got the IPv6 address*/
           sysevent_set(sysevent_fd_gs, sysevent_token_gs, "firewall-restart", "",0);
       }
#endif
       printf("Stopping wan service\n");
       GWPROV_PRINT(" Stopping wan service\n");
       t2_event_d("RF_ERROR_WAN_stop", 1);
       v_secure_system("sysevent set wan-stop");
   #ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
       v_secure_system("sysevent set dhcpv6_client-stop");
   #endif
    }

    return 0;
}


static int GWP_act_DocsisLinkUp_callback()
{
    phylink_wan_state = 1;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "phylink_wan_state", "up", 0);
    printf("\n**************************\n");
    printf("\nsysevent set phylink_wan_state up\n");
    printf("\n**************************\n\n");

    
#if defined(_PLATFORM_RASPBERRYPI_)
     char *temp;
     char wanPhyName[20];
     char out_value[20];
     int outbufsz = sizeof(out_value);
     errno_t rc = -1;

    char* buff = NULL;
    buff = malloc(sizeof(char)*50);
    if(buff == NULL)
    {
        return -1;
    }

    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
	rc = strcpy_s(wanPhyName,sizeof(wanPhyName),out_value);
    if(rc != EOK)
	{
            ERR_CHK(rc);
	    return -1;
	}

        printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
        if(buff != NULL)
            free(buff);
        return -1;
    }

    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf /*&& bridge_mode == 0*/) // mipieper - pseduo bridge support
    {
        printf("Starting wan service\n");
        v_secure_system("sysevent set wan-start ; sysevent set sshd-restart");
        sleep(50);
        v_secure_system("sysevent set current_ipv4_link_state up");
        v_secure_system("sysevent set ipv4_wan_ipaddr `ifconfig erouter0 | grep 'inet addr' | cut -d':' -f2 | awk '{print$1}'`");
        v_secure_system("sysevent set ipv4_wan_subnet `ifconfig erouter0 | grep 'inet addr' | cut -d':' -f4 | awk '{print$1}'`");
        v_secure_system("sysevent set wan_service-status started");
        v_secure_system("sysevent set bridge_mode `syscfg get bridge_mode`");
    }
    if(buff != NULL)
        free(buff);
#else
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf /*&& bridge_mode == 0*/) // mipieper - pseduo bridge support
    {
        printf("Starting wan service\n");
        GWPROV_PRINT(" Starting wan service\n");
	sysevent_set(sysevent_fd_gs, sysevent_token_gs, "wan-start", "", 0);
	sysevent_set(sysevent_fd_gs, sysevent_token_gs, "sshd-restart", "", 0);
    #ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
	sysevent_set(sysevent_fd_gs, sysevent_token_gs, "dhcpv6_client-start", "", 0);
    #endif
    }

#endif
    return 0;
}


#if defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn void *GWP_linkstate_threadfunc(void *)
 **************************************************************************
 *  \brief Thread function to check the link state
 *  \return
 **************************************************************************/
static void *GWP_linkstate_threadfunc(void *data)
{
    char *temp;
    char wanPhyName[20] = {0};
    char out_value[20] = {0};
    int outbufsz = sizeof(out_value);
    errno_t rc = -1;
    int ind = -1;

    char buff[50] = { 0 };

    char previousLinkStatus[10] = "down";
    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
		rc = strcpy_s(wanPhyName,sizeof(wanPhyName),out_value);
        if(rc != EOK)
        {
            ERR_CHK(rc);
	    return;
        }
        printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
        return (void *) -1;
    }

    while(1)
    {
        FILE *fp;
        rc =  memset_s(buff,sizeof(buff), 0, sizeof(buff));
        ERR_CHK(rc);
        /* Open the command for reading. */
        fp = v_secure_popen("r", "cat /sys/class/net/%s/operstate", wanPhyName);
        if (fp == NULL)
        {
            printf("<%s>:<%d> Error popen\n", __FUNCTION__, __LINE__);
            continue;
        }

        /* Read the output a line at a time - output it. */
        while (fgets(buff, 50, fp) != NULL)
        {
            /*printf("Ethernet status :%s", buff);*/
            temp = strchr(buff, '\n');
            if(temp)
                *temp = '\0';
        }

        /* close */
        v_secure_pclose(fp);
        rc = strcmp_s(buff, strlen(buff),(const char *)previousLinkStatus, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            /*printf("Link status not changed\n");*/
        }
        else
        {
            rc = strcmp_s("up", strlen("up"),buff, &ind);
            ERR_CHK(rc);
            if ((!ind) && (rc == EOK))
            {
                /*printf("Ethernet status :%s\n", buff);*/
                GWP_act_DocsisLinkUp_callback();
            }
            else
            {
                rc = strcmp_s("down", strlen("down"),buff, &ind);
                ERR_CHK(rc);
                if ((!ind) && (rc == EOK))
                {
                /*printf("Ethernet status :%s\n", buff);*/
                GWP_act_DocsisLinkDown_callback_1();
                GWP_act_DocsisLinkDown_callback_2();
                }
                else
                {
                   sleep(5);
                   continue;
                }
            }
            
            rc =  memset_s(previousLinkStatus,sizeof(previousLinkStatus), 0, sizeof(previousLinkStatus));
            ERR_CHK(rc);
	    rc = strcpy_s((char *)previousLinkStatus,sizeof(previousLinkStatus),buff);
            if(rc != EOK)
            {
               ERR_CHK(rc);
	       return;
            }

            /*printf("Previous Ethernet status :%s\n", (char *)previousLinkStatus);*/
        }
        sleep(5);
    }

    return 0;
}
#endif

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

/* GWP_UpdateTr069CfgThread() */
#if !defined(_PLATFORM_RASPBERRYPI_)
static void *GWP_UpdateTr069CfgThread( void *data )
{
	int 	IsNeedtoProceedFurther    = TRUE;

	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);

	pthread_detach( pthread_self( ) );

	//Check whether TLV binary is present or not
	if( 0 == IsFileExists( TR69_TLVDATA_FILE ) || (tlvObject == NULL))
	{
		GWPROV_PRINT(" %s file not present \n", TR69_TLVDATA_FILE );
		IsNeedtoProceedFurther = FALSE;
	}

	//Proceed Further
	if( IsNeedtoProceedFurther )
	{
		char	output[ 16 ] = { 0 };

		//Get Tr069 process PID
		GWP_Util_get_shell_output( "pidof CcspTr069PaSsp", output, sizeof( output ) );
		
		/*
		 * Check Tr069 process is running or not. If not then no need to configure TLV data because it will get 
		 * update during Tr069 process initialization. so break the loop
		 */
		if( ( '\0' == output[ 0 ] ) || ( 0 == strlen( output ) ) )
		{
			GWPROV_PRINT("%s CcspTr069PaSsp is not running. No need to configure\n", __FUNCTION__);
			IsNeedtoProceedFurther= FALSE;
		}
		else
		{
			//Get the PID
			GWPROV_PRINT("%s CcspTr069PaSsp is running PID:%s\n", __FUNCTION__, output );
		}
		
		//Proceed further
		if( IsNeedtoProceedFurther )
		{
			int 	TotalWaitTime	= 300;
		
			//Check whether TLV parsing got missed by Tr069 or not
			if( 0 == access( "/tmp/.TLVmissedtoparsebytr069" , F_OK ) )
			{
				GWPROV_PRINT("%s CcspTr069PaSsp has missed to parse %s file\n", __FUNCTION__, TR69_TLVDATA_FILE );
		
				while( 1 )
				{
					//Get Tr069 process ready status
					if( 0 == access( "/var/tmp/tr069paready" , F_OK ) )
					{
						//Tr069 process is ready to receive DBUS signal. so proceed to set call
						char cmd[ 512 ];

						//Wait for 5seconds after system ready signal
						sleep( 5 );

						GWPROV_PRINT("%s CcspTr069PaSsp has ready so update boot cfg data\n", __FUNCTION__);
					
						//Set the Enable CWMP parameter
						v_secure_system("dmcli eRT setvalues Device.ManagementServer.EnableCWMP bool      %d ", tlvObject->EnableCWMP);
						GWPROV_PRINT(" %s \n",cmd);
					
						/*
						  * Set the URL parameter
						  * When FreshBootUp == TRUE
						  * When FreshBootUp == FALSE && 	Tr69Enable == FALSE					  
						  */
						
						if( ( TRUE == tlvObject->FreshBootUp ) || \
							( ( FALSE == tlvObject->FreshBootUp ) && ( tlvObject->Tr69Enable == FALSE ) )
						  )
						{
							if( '\0' != tlvObject->URL[ 0 ] )
							{
								v_secure_system("dmcli eRT setvalues Device.ManagementServer.URL string %s ", tlvObject->URL);
								GWPROV_PRINT(" %s \n",cmd);
							}

							if (TRUE == tlvObject->FreshBootUp)
							{
								tlvObject->FreshBootUp = FALSE;
								FILE *TLVDataFile = fopen(TR69_TLVDATA_FILE, "wb");
								if (TLVDataFile != NULL)
								{
									fwrite(tlvObject, sizeof(Tr69TlvData), 1, TLVDataFile);
									fclose(TLVDataFile);
								}
							}
						}

						break;
					}
					else
					{
						//Wait for 10seconds to get system ready signal
						sleep( 10 );
						TotalWaitTime = TotalWaitTime - 10;

						//Wait till 5Minutes after Tr069 coming up otherwise quit the loop
						if(  0 >= TotalWaitTime )
						{
							GWPROV_PRINT("%s CcspTr069PaSsp has not coming up even after 5minutes. so breaking loop\n", __FUNCTION__);
							break;
						}
					}
				}
			}
			else
			{
				IsNeedtoProceedFurther = FALSE;
				GWPROV_PRINT("%s CcspTr069PaSsp might be parsed %s file\n", __FUNCTION__, TR69_TLVDATA_FILE );
			}
		}
	}
	
	GWPROV_PRINT(" Exit %s \n", __FUNCTION__);
        return data;
}
#endif
#if !defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn int GWP_act_DocsisCfgfile(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Parse Config File
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_act_DocsisCfgfile_callback(Char* cfgFile)
{
    Char *cfgFileName = NULL;
    struct stat cfgFileStat;
    Uint8 *cfgFileBuff = NULL;
    Uint32 cfgFileBuffLen;
    int cfgFd;
    ssize_t actualNumBytes;
	pthread_t Updatetr069CfgThread = (pthread_t)NULL;

    //TlvParseStatus_e tlvStatus;
    TlvParsingStatusExtIf_e tlvStatus;
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    
    GWPROV_PRINT("GWP_act_DocsisCfgfile_callback : The Previous EROUTERMODE=%d\n",eRouterMode);
    GWPROV_PRINT("GWP_act_DocsisCfgfile_callback : The Previous BRIDGE MODE=%d\n",bridge_mode);
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    GWPROV_PRINT("GWP_act_DocsisCfgfile_callback : The Refreshed EROUTERMODE=%d\n",eRouterMode);
    GWPROV_PRINT("GWP_act_DocsisCfgfile_callback : The Refreshed BRIDGE MODE=%d\n",bridge_mode);

    oldRouterMode = eRouterMode;

    if( cfgFile != NULL)
    {
      cfgFileName = cfgFile;
      printf("Got CfgFile \"%s\"\n", cfgFileName);
	GWPROV_PRINT(" cfgFileName = %s\n", cfgFileName);
    }
    else
    {
	GWPROV_PRINT(" cfgFile is NULL\n");
       goto gimReply;
    }

    v_secure_system("sysevent set docsis_cfg_file %s", cfgFileName);

    printf("sysevent set docsis_cfg_file %s\n", cfgFileName);

    if (stat(cfgFileName, &cfgFileStat) != 0)
    {
        printf("Cannot stat eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        GWPROV_PRINT(" Cannot stat eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        goto gimReply;
    }
    cfgFileBuffLen = cfgFileStat.st_size;
    if (cfgFileBuffLen == 0)
    {
        /* No eSafe TLVs --> No eRouter TLVs */
        printf("CfgFile \"%s\" is empty\n", cfgFileName);
        GWPROV_PRINT(" CfgFile \"%s\" is empty\n", cfgFileName);
        goto gimReply;
    }

    cfgFileBuff = malloc(cfgFileBuffLen);
    if (cfgFileBuff == NULL)
    {
        /* Coverity Issue Fix - CID:125400  : Printf Args*/
        printf("Cannot alloc buffer for eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        GWPROV_PRINT(" Cannot alloc buffer for eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        goto gimReply;
    }

    if ((cfgFd = open(cfgFileName, O_RDONLY)) < 0)
    {
        printf("Cannot open eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        GWPROV_PRINT(" Cannot open eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        goto freeMem;
    }

    if ((actualNumBytes = read(cfgFd, cfgFileBuff, cfgFileBuffLen)) < 0)
    {
        printf("Cannot read eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        GWPROV_PRINT(" Cannot read eSafe Config file \"%s\", %s, aborting Config file\n", cfgFileName, strerror(errno));
        goto closeFile;
    }
    else if (actualNumBytes != cfgFileBuffLen)
    {
        printf("eSafe Config file \"%s\", actual len (%d) different than stat (%d), aborting Config file\n", cfgFileName, actualNumBytes, cfgFileBuffLen);
        GWPROV_PRINT(" eSafe Config file \"%s\", actual len (%d) different than stat (%d), aborting Config file\n", cfgFileName, actualNumBytes, cfgFileBuffLen);
        goto closeFile;
    }

    
    tlvStatus = parseTlv(cfgFileBuff, cfgFileBuffLen);

    if (tlvStatus != TLV_OK_extIf)
    {
        printf("eSafe Config file \"%s\", parsing error (%d), aborting Config file\n", cfgFileName, tlvStatus);
        GWPROV_PRINT(" eSafe Config file \"%s\", parsing error (%d), aborting Config file\n", cfgFileName, tlvStatus);
        goto closeFile;
    }

    printf("eSafe Config file \"%s\", parsed completed, status %d\n", cfgFileName, tlvStatus);
    GWPROV_PRINT(" eSafe Config file \"%s\", parsed completed, status %d\n", cfgFileName, tlvStatus);
    //GW_UpdateTr069Cfg();

	//Start GWP_UpdateTr069CfgThread 
    GWPROV_PRINT("GWP_UpdateTr069CfgThread started\n");
	pthread_create( &Updatetr069CfgThread, NULL, &GWP_UpdateTr069CfgThread, NULL );  

#if defined (INTEL_PUMA7)
    //Intel Proposed RDKB Generic Bug Fix from XB6 SDK  
    //Notifying the CcspPandM and CcspTr069 module that the TLV parsing is successful and done
    v_secure_system("sysevent set TLV202-status success");
#endif

closeFile:
    /* Close file */
    if (cfgFd >= 0)
    {
        close(cfgFd);
    }
freeMem:
    /* Free memory */
    if (cfgFileBuff != NULL)
    {
        free(cfgFileBuff);
    }
gimReply:

    /* Reply to GIM SRN */
    notificationReply_CfgFileForEsafe();
    
    GWP_UpdateERouterMode();

    return 0;
}

/**************************************************************************/
/*! \fn int GWP_act_StartActiveUnprovisioned(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions for starting active gw, before DOCSIS cfg file
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
//static int GWP_act_StartActiveUnprovisioned(SME_APP_T *app, SME_EVENT_T *event)
static int GWP_act_StartActiveUnprovisioned()
{
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    /* Update esafe db with router provisioning status*/
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_IN_PROGRESS_extIf);
	
    printf("Starting ActiveUnprovisioned processes\n");

#if !defined(INTEL_PUMA7)
    Char *cmdline;
    /* Add paths for eRouter dev counters */
    printf("Adding PP paths\n");
    cmdline = "add "IFNAME_ETH_0" cni0 " ER_NETDEVNAME " in";
    COMMONUTILS_file_write("/proc/net/ti_pp_path", cmdline, strlen(cmdline));
    cmdline = "add cni0 "IFNAME_ETH_0" " ER_NETDEVNAME " out";
    COMMONUTILS_file_write("/proc/net/ti_pp_path", cmdline, strlen(cmdline));
#endif

    /*printf("Starting COSA services\n");
    system("sh /etc/utopia/service.d/service_cosa.sh cosa-start");*/
    
    /* Start webgui in PCD after P&M is fully initialized */
    /*
    printf("Starting WebGUI\n");
    system("sh /etc/webgui.sh");
    */
    return 0;
}

/**************************************************************************/
/*! \fn int GWP_act_InactiveBefCfgfile(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions for inactive gw, before DOCSIS cfg file
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
//static int GWP_act_InactiveBefCfgfile(SME_APP_T *app, SME_EVENT_T *event)
static int GWP_act_InactiveBefCfgfile()
{
    /* Update esafe db with router provisioning status*/
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_NOT_INITIATED_extIf);

    printf("******************************\n");
    printf("* Disabled (before cfg file) *\n");
    printf("******************************\n");

    /*printf("Starting forwarding service\n");
    system("sysevent set forwarding-start");*/

    /*printf("Starting COSA services\n");
    system("sh /etc/utopia/service.d/service_cosa.sh cosa-start");*/

    /*printf("Starting WebGUI\n");
    system("sh /etc/webgui.sh");*/

    return 0;
}

/**************************************************************************/
/*! \fn int GWP_act_BefCfgfileEntry(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions at entry to BefCfgfile
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
//static int GWP_act_BefCfgfileEntry_callback(SME_APP_T *app, SME_EVENT_T *event)
static int GWP_act_BefCfgfileEntry_callback()
{
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    if (GWP_IsGwEnabled())
    {
        
        return GWP_act_StartActiveUnprovisioned();
    }
    else
    {
        
        return GWP_act_InactiveBefCfgfile();
    }
}
#endif

/**************************************************************************/
/*! \fn int GWP_act_DocsisInited(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions when DOCSIS is initialized
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_act_DocsisInited_callback()
{
    esafeErouterOperModeExtIf_e operMode;
    //DOCSIS_Esafe_Db_Enable_e eRouterModeTmp; 
#if !defined(_PLATFORM_RASPBERRYPI_)
    DOCSIS_Esafe_Db_extIf_e eRouterModeTmp;
#endif
    Uint8 lladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ] = {0};
    Uint8 soladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ] = {0};
    char soladdrKey[64] = { 0 };
    /* Coverity Issue Fix - CID:73933 : UnInitialised variable */
    char soladdrStr[64] = {0};
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(INTEL_PUMA7)
    /* Docsis initialized */
    printf("Got DOCSIS Initialized\n");

    // printf("Utopia init done\n");
    printf("Loading erouter0 network interface driver\n");
	GWPROV_PRINT(" Loading erouter0 network interface driver\n");
    v_secure_system("insmod " ERNETDEV_MODULE " netdevname=" ER_NETDEVNAME);

    {
        macaddr_t macAddr;
        
        getWanMacAddress(&macAddr);
       
       setNetworkDeviceMacAddress(ER_NETDEVNAME,&macAddr);
    }  

    
    getDocsisDbFactoryMode(&factory_mode);
#endif
	GWPROV_PRINT(" factory_mode %d \n", factory_mode);
    if (factory_mode) {
        //GWP_SysCfgSetInt("bridge_mode", 2);
        GWP_SysCfgSetInt("mgmt_lan_telnetaccess", 1);
        //GWP_SysCfgSetInt("last_erouter_mode", 0);
     }

#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
	printf("Not Initializing bridge_mode and eRouterMode for XB3\n");
#else
    int sysevent_bridge_mode = 0;
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;
#endif
//     mipieper - remove for pseudo bridge support. Could add back depending on policy. 
//     if (bridge_mode == 0)
//     {
//
//         bridge_mode = eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf ? 2 : 0;
//     }
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
	printf("Not Initializing bridge_mode and eRouterMode for XB3\n");
#elif defined(_PLATFORM_RASPBERRYPI_)
    printf("Not Initializing bridge_mode and eRouterMode for Raspberry Pi\n");
#else
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    validate_mode(&bridge_mode, (int*)&eRouterMode);
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;
	GWPROV_PRINT(" active_mode %d \n", active_mode);
    v_secure_system("sysevent set bridge_mode %d", sysevent_bridge_mode);
#endif
  
#if !defined(_PLATFORM_RASPBERRYPI_)
    GWP_DocsisInited();
#endif

#if defined(_PROPOSED_BUG_FIX_)
	/* Setting erouter0 MAC address after Docsis Init */
    printf("Loading erouter0 network interface driver\n");
    {
       macaddr_t macAddr;

       getNetworkDeviceMacAddress(&macAddr);

       setNetworkDeviceMacAddress(ER_NETDEVNAME,&macAddr);
    }
#endif

      v_secure_system("sysevent set docsis-initialized 1");
#if !defined(_PLATFORM_RASPBERRYPI_)

    /* Must set the ESAFE Enable state before replying to the DocsisInit event */
    eRouterModeTmp = eRouterMode;
//      mipieper - remove for pseudo bridge support. Partial bridge should not force global bridge.
//     if(bridge_mode == 2) 
//         eRouterModeTmp = DOCESAFE_ENABLE_DISABLE;
    GWP_UpdateEsafeAdminMode(eRouterModeTmp);
	GWPROV_PRINT(" eRouterModeTmp = %d\n", eRouterModeTmp);
    /* Set operMode */
    //if (eRouterMode == DOCESAFE_ENABLE_DISABLE)
    if (eRouterModeTmp == DOCESAFE_ENABLE_DISABLE_extIf)
    {
        /* Disabled */
        operMode = DOCESAFE_EROUTER_OPER_DISABLED_extIf;
    }
    else
    {
        /* At this point: enabled, but neither are provisioned (regardless of which is enabled) */
        operMode = DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6_extIf;
    }
        GWPROV_PRINT(" operMode = %d\n", operMode);
    eSafeDevice_SetErouterOperationMode(operMode);

  
   	eSafeDevice_SetServiceIntImpact();

    /* Disconnect docsis LB */
    printf("Disconnecting DOCSIS local bridge\n");
        GWPROV_PRINT(" Disconnecting DOCSIS local bridge\n");
    connectLocalBridge(False);

    /* This is an SRN, reply */
    printf("Got Docsis INIT - replying\n");
   
    notifyDocsisInitializedResponse();

    
    //calcualte erouter base solicited node address
   
    getInterfaceLinkLocalAddress(ER_NETDEVNAME, lladdr);
    
    getMultiCastGroupAddress(lladdr,soladdr);
#endif

    snprintf(soladdrKey, sizeof(soladdrKey), "ipv6_%s_ll_solicNodeAddr", ER_NETDEVNAME);
    inet_ntop(AF_INET6, soladdr, soladdrStr, sizeof(soladdrStr));
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, soladdrKey, soladdrStr,0);

    unsigned char lan_wan_ready = 0;
    char result_buf[32];
    result_buf[0] = '\0';

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, "start-misc", result_buf, sizeof(result_buf));
    lan_wan_ready = strstr(result_buf, "ready") == NULL ? 0 : 1;
        GWPROV_PRINT(" lan_wan_ready = %d\n", lan_wan_ready);
    if(!lan_wan_ready) {
        v_secure_system("ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", ER_NETDEVNAME, soladdrStr);
    }

    //calculate cm base solicited node address
#if !defined(_PLATFORM_RASPBERRYPI_)
    getInterfaceLinkLocalAddress(IFNAME_WAN_0, lladdr);
    
   
    getMultiCastGroupAddress(lladdr,soladdr);
#endif
    snprintf(soladdrKey, sizeof(soladdrKey), "ipv6_%s_ll_solicNodeAddr", IFNAME_WAN_0);
    inet_ntop(AF_INET6, soladdr, soladdrStr, sizeof(soladdrStr));
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, soladdrKey, soladdrStr,0);

    if(!lan_wan_ready) {
        v_secure_system("ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", IFNAME_WAN_0, soladdrStr);
    }
    
    //StartDocsis();

    return 0;
}


/**************************************************************************/
/*! \fn int DCR_act_ProvEntry(SME_APP_T *app, SME_EVENT_T *event);
 **************************************************************************
 *  \brief Actions at entry to gw provisioning
 *  \param[in] SME Handler params
 *  \return 0
**************************************************************************/
static int GWP_act_ProvEntry_callback()
{
#if defined(_PLATFORM_RASPBERRYPI_)
    int uid = 0;
    uid = getuid();
#endif
    int sysevent_bridge_mode = 0;
#ifdef MULTILAN_FEATURE
    macaddr_t macAddr;
#endif
#if !defined(_PLATFORM_RASPBERRYPI_)
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    //system("sysevent set lan-start");
   
/* TODO: OEM to implement swctl apis */

    /* Register on docsis Init event */
#if !defined(INTEL_PUMA7) 
    GWPROV_PRINT(" registerDocsisInitEvents \n");    
    registerDocsisInitEvents();
#endif
    GWPROV_PRINT(" Calling /etc/utopia/utopia_init.sh \n"); 
    v_secure_system("/etc/utopia/utopia_init.sh");

    syscfg_init();
    if (0 != GWP_SysCfgGetInt("bridge_mode"))
    {
        bridgeModeInBootup = 1;
    }
#else
    v_secure_system("mkdir -p /nvram");
    v_secure_system("rm -f /nvram/dnsmasq.leases");
    v_secure_system("syslogd -f /etc/syslog.conf");

    //copy files that are needed by CCSP modules
    v_secure_system("cp /usr/ccsp/ccsp_msg.cfg /tmp");
    v_secure_system("touch /tmp/cp_subsys_ert");

    /* Below link is created because crond is expecting /crontabs/ dir instead of /var/spool/cron/crontabs */
    v_secure_system("ln -s /var/spool/cron/crontabs /");
    /* directory /var/run/firewall because crond is expecting this dir to execute time specific blocking of firewall*/
    v_secure_system("mkdir -p /var/run/firewall");

    v_secure_system("/etc/utopia/utopia_init.sh");

    syscfg_init();

    sleep(2);

    char command[50];
    char wanPhyName[20];
    char out_value[20];
    int outbufsz = sizeof(out_value);
    errno_t rc = -1;
    char previousLinkStatus[10] = "down";
    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
       rc = strcpy_s(wanPhyName,sizeof(wanPhyName),out_value);
       if(rc != EOK)
       {
          ERR_CHK(rc);
          return -1;
       }
       printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
       return -1;
    }

    v_secure_system("ifconfig eth0 down");
    rc =  memset_s(command,sizeof(command), 0, sizeof(command));
    ERR_CHK(rc);
    printf("****************value of command = ip link set eth0 name %s**********************\n", wanPhyName);
    v_secure_system("ip link set eth0 name %s", wanPhyName);

    rc =  memset_s(command,sizeof(command), 0, sizeof(command));
    ERR_CHK(rc);
    printf("************************value of command = ifconfig %s up ***********************\n", wanPhyName);
    v_secure_system("ifconfig %s up", wanPhyName);
#endif
#if defined(_PLATFORM_RASPBERRYPI_)
if( uid == 0 )
{
#endif
    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov", &sysevent_token);

    if (sysevent_fd >= 0)
    {
        v_secure_system("sysevent set phylink_wan_state down");
        GWPROV_PRINT(" Creating Thread  GWP_sysevent_threadfunc \n"); 
        pthread_create(&sysevent_tid, NULL, GWP_sysevent_threadfunc, NULL);
    }
#ifdef AUTOWAN_ENABLE
#ifdef INTEL_PUMA7
    if(!IsFileExists(ETHWAN_FILE))
    {
    	AutoWAN_main();
    }
#else
	AutoWAN_main();
#endif
#endif
#if defined(_PLATFORM_RASPBERRYPI_)
}
#endif      
    //Make another connection for gets/sets
#if defined(_PLATFORM_RASPBERRYPI_)
if ( uid == 0 )
{
#endif
    sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov-gs", &sysevent_token_gs);
#if defined(_PLATFORM_RASPBERRYPI_)
}
#endif
// rdkb rpi container :: lxcserver funbction is needed to run in host for listening event from ccsppandm
#if defined(_PLATFORM_RASPBERRYPI_)
    if( uid == 0 )
    {
        //rdkb rpi container :: lxc-server thread create
        GWPROV_PRINT(" Creating Thread  GWP_lxcserver_threadfunc \n");
        pthread_create(&lxcserver_tid, NULL, GWP_lxcserver_threadfunc, NULL);
    }
#endif
    /*if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf)
    {
        printf("Utopia init done, starting lan\n");
        system("sysevent set lan-start");
    }*/

    printf("Waiting for Docsis INIT\n");

#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");

    validate_mode(&bridge_mode, (int*)&eRouterMode);
    
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;
	GWPROV_PRINT(" active_mode %d \n", active_mode);
#else
	printf("Non-XB3 case bridge_mode and eRouterMode are already initialized\n");
#endif

    v_secure_system("sysevent set bridge_mode %d", sysevent_bridge_mode);

    /* Now that we have the ICC que (SME) and we are registered on the docsis INIT    */
    /* event, we can notify PCD to continue                                           */
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(INTEL_PUMA7)
    sendProcessReadySignal();
#endif

    /* Initialize Switch */
    // VEN_SWT_InitSwitch();

#if defined(_PLATFORM_RASPBERRYPI_)
    printf("Thread to monitor link status \n");
    pthread_create(&linkstate_tid, NULL, GWP_linkstate_threadfunc, NULL);
#endif

#ifdef MULTILAN_FEATURE
    char sysevent_cmd[80] = { 0 };
    /* Update LAN side base mac address */
    getNetworkDeviceMacAddress(&macAddr);
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "%02x:%02x:%02x:%02x:%02x:%02x",
        macAddr.hw[0],macAddr.hw[1],
        macAddr.hw[2],macAddr.hw[3],
        macAddr.hw[4],macAddr.hw[5]);
    if ((syscfg_set(NULL, BASE_MAC_SYSCFG_KEY, sysevent_cmd) != 0))
    {
        fprintf(stderr, "Error in %s: Failed to set %s!\n", __FUNCTION__, BASE_MAC_SYSCFG_KEY);
    }

    /* Update LAN bridge mac address offset */
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "%d", BASE_MAC_BRIDGE_OFFSET);
    if ((syscfg_set(NULL, BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY, sysevent_cmd) != 0))
    {
        fprintf(stderr, "Error in %s: Failed to set %s!\n", __FUNCTION__, BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY);
    }

    /* Update wired LAN interface mac address offset */
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "%d", BASE_MAC_LAN_OFFSET);
    if ((syscfg_set(NULL, BASE_MAC_LAN_OFFSET_SYSCFG_KEY, sysevent_cmd) != 0))
    {
        fprintf(stderr, "Error in %s: Failed to set %s!\n", __FUNCTION__, BASE_MAC_LAN_OFFSET_SYSCFG_KEY);
    }

    /* Update WiFi interface mac address offset */
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "%d", BASE_MAC_WLAN_OFFSET);
    if ((syscfg_set(NULL, BASE_MAC_WLAN_OFFSET_SYSCFG_KEY, sysevent_cmd) != 0))
    {
        fprintf(stderr, "Error in %s: Failed to set %s!\n", __FUNCTION__, BASE_MAC_WLAN_OFFSET_SYSCFG_KEY);
    }
#endif

    return 0;
}

#if !defined(_PLATFORM_RASPBERRYPI_)
static int GWP_act_DocsisTftpOk_callback(){
	GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    gDocTftpOk = 1;
    if(snmp_inited) {
        
         if(startDocsisCfgParsing() != STATUS_OK) {
            printf("fail to start docsis CFG parsing!!\n");
        }
    }
    return 0;
}

// static int get_ipv6_addrs() {
//     
// }

// static int GWP_act_DocsisDHCPv6Bind(SME_APP_T *app, SME_EVENT_T *event){
//     
// }

/*static void StartDocsis() {
    if(DocsisIf_StartDocsisManager() != STATUS_OK)
    {
       LOG_GW_ERROR("fail to start docsis!!\n");
    }
    return;
}*/
#endif

static void LAN_start() {
#ifdef RDKB_DSLITE
    char _4_to_6_status[2]={0};
    int dslite_enable=0;
#endif
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
    
#ifdef RDKB_DSLITE
/* Check if 4_to_6 tunnel support is enabled */
    syscfg_get(NULL, "4_to_6_enabled", _4_to_6_status, sizeof(_4_to_6_status));
    dslite_enable = atoi(_4_to_6_status);
    if (dslite_enable == 1)
    {
        GWPROV_PRINT(" Setting dslite_enabled event \n");
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "dslite_enabled", "1", 0);
    }
#endif

    //ADD MORE LAN NETWORKS HERE
    GWPROV_PRINT(" Setting dhcp_server-resync event \n");     
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "dhcp_server-resync", "", 0);
   
	/* TODO: OEM to implement swctl apis */

    if(gDocTftpOk) {
        if(startDocsisCfgParsing() != STATUS_OK) {
            printf("fail to start docsis CFG parsing!!\n");
        }
    }
    return;
}

void _get_shell_output(FILE *fp, char *buf, int len)
{
    char * p;

    if (fp)
    {
        if(fgets (buf, len-1, fp) != NULL)
        {
            buf[len-1] = '\0';
            if ((p = strchr(buf, '\n'))) {
                *p = '\0';
            }
        }
    v_secure_pclose(fp);
    }
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
#if defined(_PLATFORM_RASPBERRYPI_)
     int uid = 0;
     uid = getuid();
#endif
    printf("Started gw_prov_utopia\n");

    t2_init("ccsp-gwprovapp");

#if !defined(_PLATFORM_RASPBERRYPI_)

    #ifdef FEATURE_SUPPORT_RDKLOG
       setenv("LOG4C_RCPATH","/rdklogger",1);
       rdk_logger_init(DEBUG_INI_NAME);
    #endif

    GWPROV_PRINT(" Entry gw_prov_utopia\n");
#if defined(FEATURE_RDKB_WAN_MANAGER)
    GWPROV_PRINT(" Calling /etc/utopia/utopia_init.sh \n");
    v_secure_system("/etc/utopia/utopia_init.sh");

    GWPROV_PRINT("wait in loop \n");
	while (1)
	{
		sleep(1);
	}
#endif

#if !defined(INTEL_PUMA7)
    if( findProcessId(argv[0]) > 0 )
    {
        printf("Already running\n");
        GWPROV_PRINT(" gw_prov_utopia already running. Returning...\n");
        return 1;
    }

    printf("Register exception handlers\n");
    
    registerProcessExceptionHandlers(argv[0]);

    GWP_InitDB();
#else
    Cgm_GatewayApiProxy_Init();
    printf("API Proxy RPC handle initialized.");
#endif //!defined(INTEL_PUMA7)

    appCallBack *obj = NULL;
    obj = (appCallBack*)malloc(sizeof(appCallBack));

    if(obj != NULL)
    {
        obj->pGWP_act_DocsisLinkDown_1 =  (fpDocsisLinkDown_1)GWP_act_DocsisLinkDown_callback_1;
        obj->pGWP_act_DocsisLinkDown_2 =  (fpDocsisLinkDown_2)GWP_act_DocsisLinkDown_callback_2;
        obj->pGWP_act_DocsisLinkUp = (fpDocsisLinkUp)GWP_act_DocsisLinkUp_callback;
        obj->pGWP_act_DocsisCfgfile = (fpDocsisCfgfile)GWP_act_DocsisCfgfile_callback;
        obj->pGWP_act_DocsisTftpOk = (fpDocsisTftpOk)GWP_act_DocsisTftpOk_callback;
        obj->pGWP_act_BefCfgfileEntry = (fpBefCfgfileEntry)GWP_act_BefCfgfileEntry_callback;
        obj->pGWP_act_DocsisInited = (fpDocsisInited)GWP_act_DocsisInited_callback;
        obj->pGWP_act_ProvEntry = (fpProvEntry)GWP_act_ProvEntry_callback;
        obj->pDocsis_gotEnable = (fpDocsisEnabled)docsis_gotEnable_callback;
        obj->pGW_Tr069PaSubTLVParse = (fpGW_Tr069PaSubTLVParse)GW_Tr069PaSubTLVParse;
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
        obj->pGW_SetTopologyMode = (fpGW_SetTopologyMode)GW_setTopologyMode;
#endif

    	GWPROV_PRINT(" Creating Event Handler\n");
    	/* Command line - ignored */
    	SME_CreateEventHandler(obj);
    	GWPROV_PRINT(" Creating Event Handler over\n");
           /*Coverity Fix CID:80015 RESOURCE_LEAK */
           free(obj);
    } //if(obj != NULL)

#else
    GWP_act_ProvEntry_callback();
    GWP_act_DocsisInited_callback();
if( uid == 0 )
{
    (void) pthread_join(sysevent_tid, NULL);
    (void) pthread_join(lxcserver_tid, NULL);
}
    (void) pthread_join(linkstate_tid, NULL);
#endif
    

    return 0;

}



