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
#if !defined(_PLATFORM_RASPBERRYPI_)
#include <sys/types.h>
#endif
#include <unistd.h>
#if !defined(_PLATFORM_RASPBERRYPI_)
#include <ruli.h>
#endif
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <pthread.h>
#include "gw_prov_abstraction.h"
#include "Tr69_Tlv.h"
#include <autoconf.h>
#if !defined(_PLATFORM_RASPBERRYPI_)
#include "docsis_esafe_db.h"
#endif
#include <time.h>
#ifdef FEATURE_SUPPORT_RDKLOG
#include "rdk_debug.h"
#endif

/* Global Variables*/
char log_buff[1024];
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
#define COMP_NAME "LOG.RDK.GWPROV"
#define LOG_INFO 4

#ifdef FEATURE_SUPPORT_RDKLOG
#define GWPROV_PRINT(fmt ...)    {\
				    				snprintf(log_buff, 1023, fmt);\
                                    RDK_LOG(LOG_INFO, COMP_NAME, "%s", log_buff);\
                                 }
#else
#define GWPROV_PRINT printf
#endif

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



/**************************************************************************/
/*      LOCAL DECLARATIONS:                                               */
/**************************************************************************/

/*! New implementation */
static void GW_Local_PrintHexStringToStderr(Uint8 *str, Uint16 len);
static void GW_SetTr069PaMibBoolean(Uint8 **cur, Uint8 sub_oid, Uint8 value);
static void GW_SetTr069PaMibString(Uint8 **cur, Uint8 sub_oid, Uint8* value);
static STATUS GW_TlvParserInit(void);
//static TlvParseCallbackStatus_e GW_SetTr069PaCfg(Uint8 type, Uint16 length, const Uint8* value);
static TlvParseCallbackStatusExtIf_e GW_Tr069PaSubTLVParse(Uint8 type, Uint16 length, const Uint8* value);
static STATUS GW_SetTr069PaDataInTLV11Buffer(Uint8* buf, Int* len);
static STATUS GW_UpdateTr069Cfg(void);
static void check_lan_wan_ready();

//static TlvParseCallbackStatus_e gotEnableType(Uint8 type, Uint16 length, const Uint8* value);
static TlvParseCallbackStatusExtIf_e GW_setTopologyMode(Uint8 type, Uint16 length, const Uint8* value);

/* New implementation !*/
static void LAN_start();

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/


static int snmp_inited = 0;
static int pnm_inited = 0;
static int netids_inited = 0;
static int gDocTftpOk = 0;
static int hotspot_started = 0;
static int lan_telnet_started = 0;
static int ciscoconnect_started = 0;
static int webui_started = 0;
static Uint32 factory_mode = 0;


static DOCSIS_Esafe_Db_extIf_e eRouterMode = DOCESAFE_ENABLE_DISABLE_extIf;
static DOCSIS_Esafe_Db_extIf_e oldRouterMode;
static int sysevent_fd;
static token_t sysevent_token;
static int sysevent_fd_gs;
static token_t sysevent_token_gs;
static pthread_t sysevent_tid;
#if defined(_PLATFORM_RASPBERRYPI_)
static pthread_t linkstate_tid;
#endif
static int phylink_wan_state = 0;
static int once = 0;
static int bridge_mode = BRMODE_ROUTER;
static int active_mode = BRMODE_ROUTER;

static GwTlvsLocalDB_t gwTlvsLocalDB;

/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
static void GWP_EnterBridgeMode(void);
static void GWP_EnterRouterMode(void);

static int getSyseventBridgeMode(int erouterMode, int bridgeMode) {
        
    //Erouter mode takes precedence over bridge mode. If erouter is disabled, 
    //global bridge mode is returned. Otherwise partial bridge or router  mode
    //is returned based on bridge mode. Partial bridge keeps the wan active
    //for networks other than the primary.
    // router = 0
    // global bridge = 2
    // partial (pseudo) = 3
	
#ifdef CONFIG_PRIMARY_NET_BRIDGE_MODE
    return erouterMode ? (bridgeMode ? BRMODE_PRIMARY_BRIDGE : BRMODE_ROUTER) : BRMODE_GLOBAL_BRIDGE;
#else 
    return erouterMode ? (bridgeMode ? BRMODE_GLOBAL_BRIDGE : BRMODE_ROUTER) : BRMODE_GLOBAL_BRIDGE;
#endif

}


#if !defined(_PLATFORM_RASPBERRYPI_)
/**************************************************************************/
/*! \fn STATUS GW_TlvParserInit(void)
 **************************************************************************
 *  \brief Initialize before the parsing
 *  \return Initialization status: OK/NOK
 **************************************************************************/
static STATUS GW_TlvParserInit(void)
{
    /*Initialize local DB*/
    // GW_FreeTranstAddrAccessList();
    memset(&gwTlvsLocalDB, 0, sizeof(gwTlvsLocalDB));

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
int IsFileExists(const char *fname)
{
    FILE *file;
    if (file = fopen(fname, "r"))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

#define TR069PidFile "/var/tmp/CcspTr069PaSsp.pid"
#define FALSE 0
#define TRUE 1
static char url[600] = {0};

static void WriteTr69TlvData(Uint8 typeOfTLV)
{
	FILE *fp;
	int bFirstNode = 0;
	int ret,tempFile;
	int isTr069Started = 0;
	char cmd[1024] = {0};
	
	
	if (objFlag == 1)
	{
		tlvObject=malloc(sizeof(Tr69TlvData));
		objFlag = 0;
	}
	/* Check if its a fresh boot-up or a boot-up after factory reset*/
	ret = IsFileExists(TR69_TLVDATA_FILE);
	isTr069Started = IsFileExists(TR069PidFile);

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
		fread(tlvObject, sizeof(Tr69TlvData), 1, file);
		fclose(file);
	}
	else
	{
		printf("TLV data file can't be opened \n");
		return;
	}

	if(tlvObject->FreshBootUp == TRUE)
	{

		switch (typeOfTLV)
		{
			case GW_SUBTLV_TR069_ENABLE_CWMP_EXTIF:
				tlvObject->EnableCWMP = gwTlvsLocalDB.tlv2.EnableCWMP;
				if(isTr069Started) 
				{
				    	sprintf(cmd, "dmcli eRT setvalues Device.ManagementServer.EnableCWMP bool  %d ",tlvObject->EnableCWMP);
					system(cmd);
                		}                  
				break;
			case GW_SUBTLV_TR069_URL_EXTIF:
				strcpy(tlvObject->URL,gwTlvsLocalDB.tlv2.URL);
				strcpy(url,tlvObject->URL);
				if(isTr069Started) 
				{
				    	sprintf(cmd, "dmcli eRT setvalues Device.ManagementServer.URL string %s ",tlvObject->URL);
                    			system(cmd); 
                		}
                		break;
			case GW_SUBTLV_TR069_USERNAME_EXTIF:                			
        		case GW_SUBTLV_TR069_PASSWORD_EXTIF:
        		case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
        		case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
        		case GW_SUBTLV_TR069_ACS_OVERRIDE_EXTIF:
				break;
			default:
				printf("TLV : %d can't be saved to TLV data file\n",typeOfTLV);
				break;
		}
	
	}
	else
	{	
		/*In case of Normal bootup*/
		tlvObject->FreshBootUp = FALSE;
		switch (typeOfTLV)
		{
			case GW_SUBTLV_TR069_ENABLE_CWMP_EXTIF:
					tlvObject->EnableCWMP = gwTlvsLocalDB.tlv2.EnableCWMP;
					if(isTr069Started) 
					{
				    		sprintf(cmd, "dmcli eRT setvalues Device.ManagementServer.EnableCWMP bool  %d ",tlvObject->EnableCWMP);
                    				system(cmd);
                			}  
					break;
			case GW_SUBTLV_TR069_URL_EXTIF:
				if(tlvObject->Tr69Enable == FALSE) 
				{
					// This is to make sure that we always use boot config supplied URL
					// during TR69 initialization
					strcpy(tlvObject->URL,gwTlvsLocalDB.tlv2.URL);
					if(isTr069Started) 
					{
				    		sprintf(cmd, "dmcli eRT setvalues Device.ManagementServer.URL string %s ",tlvObject->URL);
                    				system(cmd);
                			}
					 
				}
				break;
			case GW_SUBTLV_TR069_USERNAME_EXTIF:                			
       			case GW_SUBTLV_TR069_PASSWORD_EXTIF:
       			case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
       			case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
       			case GW_SUBTLV_TR069_ACS_OVERRIDE_EXTIF:
				break;
			default:
				printf("TLV : %d can't be saved to TLV data file\n",typeOfTLV);
				break;
		}
	}

	file= fopen(TR69_TLVDATA_FILE, "wb");
	if (file != NULL)
	{
		fseek(file, 0, SEEK_SET);
		fwrite(tlvObject, sizeof(Tr69TlvData), sizeof(tlvObject), file);
		fclose(file);		
	}
	

}

static TlvParseCallbackStatusExtIf_e GW_Tr069PaSubTLVParse(Uint8 type, Uint16 length, const Uint8* value)
{
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
                memcpy(gwTlvsLocalDB.tlv2.URL, value, length);
                gwTlvsLocalDB.tlv2.URL[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.URL_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.URL[0] = '\0';
            break;

        case GW_SUBTLV_TR069_USERNAME_EXTIF:
            if (length <= GW_TR069_TLV_MAX_USERNAME_LEN) 
            {
                memcpy(gwTlvsLocalDB.tlv2.Username, value, length);
                gwTlvsLocalDB.tlv2.Username[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.Username_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.Username[0] = '\0';
            break;

        case GW_SUBTLV_TR069_PASSWORD_EXTIF:
            if (length <= GW_TR069_TLV_MAX_PASSWORD_LEN) 
            {
                memcpy(gwTlvsLocalDB.tlv2.Password, value, length);
                gwTlvsLocalDB.tlv2.Password[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.Password_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.Password[0] = '\0'; 
            break;

        case GW_SUBTLV_TR069_CONNREQ_USERNAME_EXTIF:
            if (length <= GW_TR069_TLV_MAX_USERNAME_LEN) 
            {
                memcpy(gwTlvsLocalDB.tlv2.ConnectionRequestUsername, value, length);
                gwTlvsLocalDB.tlv2.ConnectionRequestUsername[length] = '\0';
                gwTlvsLocalDB.tlv2_flags.ConnectionRequestUsername_modified = 1;
            }
            else gwTlvsLocalDB.tlv2.ConnectionRequestUsername[0] = '\0';
            break;

        case GW_SUBTLV_TR069_CONNREQ_PASSWORD_EXTIF:
            if (length <= GW_TR069_TLV_MAX_PASSWORD_LEN) 
            {
                memcpy(gwTlvsLocalDB.tlv2.ConnectionRequestPassword, value, length);
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
            printf("Unknown Sub TLV In TLV 2");
            break;
    }
			
    WriteTr69TlvData(type); 
    return TLV_PARSE_CALLBACK_OK_EXTIF;
}

// All MIB entries in hex are: 30 total_len oid_base oid_value 00 data_type data_len data

// Oid_Base = 1.3.6.1.4.1.1429.79.6.1
static Uint8 GW_Tr069PaMibOidBase[12] = { 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8b, 0x15, 0x4f, 0x06, 0x01 }; 

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

static void GW_SetTr069PaMibBoolean(Uint8 **cur, Uint8 sub_oid, Uint8 value)
{
    Uint8 *mark;
    Uint8 *current = *cur;

    // SEQUENCE (0x30); Skip total length (1-byte, to be filled later)
    *(current++) = 0x30; current++; mark = current; 
    memcpy(current, GW_Tr069PaMibOidBase, 12);  current += 12;  
    *(current++) = sub_oid;
    *(current++) = GW_TR069_MIB_SUB_OID_INSTANCE_NUM;
    *(current++) = GW_TR069_MIB_DATATYPE_BOOL; 
    *(current++) = GW_TR069_MIB_DATATYPE_LEN_BOOL;
    *(current++) = value;
    *(mark-1) = (Uint8)(current - mark);

    *cur = current;
}

static void GW_SetTr069PaMibString(Uint8 **cur, Uint8 sub_oid, Uint8* value)
{
    Uint8 *mark;
    Uint8 *current = *cur;

    // SEQUENCE (0x30); Skip total length (1-byte, to be filled later)
    *(current++) = 0x30; current++; mark = current; 
    memcpy(current, GW_Tr069PaMibOidBase, 12);  current += 12;  
    *(current++) = sub_oid;
    *(current++) = GW_TR069_MIB_SUB_OID_INSTANCE_NUM;
    *(current++) = GW_TR069_MIB_DATATYPE_STRING; 
    *(current++) = (Uint8)strlen(value);
    if(*(current-1)) { memcpy(current, value, *(current-1)); current += *(current-1);}
    *(mark-1) = (Uint8)(current - mark);

    *cur = current;
}

static STATUS GW_SetTr069PaDataInTLV11Buffer(Uint8* buf, Int* len)
{
    Uint8 *ptr = buf;

    // EnableCWMP
    if(gwTlvsLocalDB.tlv2_flags.EnableCWMP_modified)
        GW_SetTr069PaMibBoolean(&ptr, GW_TR069_MIB_SUB_OID_ENABLE_CWMP, (Uint8)(gwTlvsLocalDB.tlv2.EnableCWMP));

    // URL
    if(gwTlvsLocalDB.tlv2_flags.URL_modified)
        GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_URL, (Uint8*)(gwTlvsLocalDB.tlv2.URL));

    // Username
    if(gwTlvsLocalDB.tlv2_flags.Username_modified)
        GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_USERNAME, (Uint8*)(gwTlvsLocalDB.tlv2.Username));

    // Password
    if(gwTlvsLocalDB.tlv2_flags.Password_modified)
        GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_PASSWORD, (Uint8*)(gwTlvsLocalDB.tlv2.Password));

    // ConnectionRequestUsername
    if(gwTlvsLocalDB.tlv2_flags.ConnectionRequestUsername_modified)
        GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_CONNREQ_USERNAME, (Uint8*)(gwTlvsLocalDB.tlv2.ConnectionRequestUsername));

    // ConnectRequestPassword
    if(gwTlvsLocalDB.tlv2_flags.ConnectionRequestPassword_modified)
        GW_SetTr069PaMibString(&ptr, GW_TR069_MIB_SUB_OID_CONNREQ_PASSWORD, (Uint8*)(gwTlvsLocalDB.tlv2.ConnectionRequestPassword));

    // ACSOverride
    if(gwTlvsLocalDB.tlv2_flags.AcsOverride_modified)
        GW_SetTr069PaMibBoolean(&ptr, GW_TR069_MIB_SUB_OID_ALLOW_DOCSIS_CONFIG, (Uint8)(gwTlvsLocalDB.tlv2.ACSOverride));

    *len = ptr - buf;

    return STATUS_OK;
}

#define SNMP_DATA_BUF_SIZE 1000

static STATUS GW_UpdateTr069Cfg(void)
{
    /* SNMP TLV's data buffer*/
    Uint8 Snmp_Tlv11Buf[SNMP_DATA_BUF_SIZE];
    Int Snmp_Tlv11BufLen = 0;
    STATUS ret = STATUS_OK;

    /*Init the data buffer*/
    memset(Snmp_Tlv11Buf, 0, SNMP_DATA_BUF_SIZE);

    /*Convert TLV 202.2 data into TLV11 data*/
    GW_SetTr069PaDataInTLV11Buffer(Snmp_Tlv11Buf, &Snmp_Tlv11BufLen);

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
        memset(tlv11Resp, 0, sizeof(SnmpaIfResponse_t)+sizeof(int));

        /* Set TLV11 whitin whole config file and TLV11 duplication test */
        ret = (STATUS)SNMPAIF_SetTLV11Config(SNMP_AGENT_CTRL_SOCK, (void *)Snmp_Tlv11Buf, (int)Snmp_Tlv11BufLen, tlv11Resp);

        if(tlv11Resp->len >= sizeof(int))
        {
            Int32 errorCode = 0;
            memcpy(&errorCode, tlv11Resp->value, sizeof(int));
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
static TlvParseCallbackStatusExtIf_e GW_setTopologyMode(Uint8 type, Uint16 length, const Uint8* value)
{
    Uint8 tpMode = *value;
    TlvParseCallbackStatusExtIf_e st = TLV_PARSE_CALLBACK_OK_EXTIF;
    char cmd[64] = {0};

    printf("TLV %d, Len %d : Topology Mode", type, length);

    if ( (tpMode == TLV202_42_FAVOR_DEPTH) || (tpMode == TLV202_42_FAVOR_WIDTH))
    {
        printf("eSafe CFG file : Found Topology Mode, val %d", tpMode);
        snprintf(cmd, sizeof(cmd), "sysevent set erouter_topology-mode %d", tpMode);
        system(cmd);
    }
    else
    {
        printf("eSafe CFG file : Found Topology Mode, illegal val %d, use default value.", tpMode);
        st = TLV_PARSE_CALLBACK_ABORT_EXTIF;
    }

    return st;
}

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

   if (!syscfg_get(NULL, name, out_value, outbufsz))
   {
      return atoi(out_value);
   }
   else
   {
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



void docsis_gotEnable_callback(Uint8 state)
{

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
    macaddr_t macAddr;
   
    /* Initialize docsis interface */
    initializeDocsisInterface();

    /* Register the eRouter  */
    getNetworkDeviceMacAddress(&macAddr);

    eSafeDevice_Initialize(&macAddr);
       
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_NOT_INITIATED_extIf);
	
     /* Add paths */
     
     eSafeDevice_AddeRouterPhysicalNetworkInterface(IFNAME_ETH_0, True);
           
     eSafeDevice_AddeRouterPhysicalNetworkInterface("usb0",True);

    /* Register on more events */
    registerDocsisEvents();
    
    if(factory_mode)
        LAN_start();

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
    /* Update ESAFE state */
    GWP_UpdateEsafeAdminMode(eRouterMode);

    eSafeDevice_SetErouterOperationMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6_extIf);
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_IN_PROGRESS_extIf);
	
#endif
    //bridge_mode = 0;
    //system("sysevent set bridge_mode 0");
    //system("sysevent set forwarding-restart");
	GWP_EnterRouterMode();
    system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string router");

    printf("******************************");
    printf("* Enabled (after cfg file)  *");
    printf("******************************");
}

//Actually enter router mode
static void GWP_EnterRouterMode(void)
{
    char sysevent_cmd[80];
	char MocaPreviousStatus[16];
	int prev;
    if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
         return;
    //mipieper - removed for psuedo bridge.
//     GWP_UpdateEsafeAdminMode(eRouterMode);
//     DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6);
//     DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_IN_PROGRESS);

//    bridge_mode = 0;
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", BRMODE_ROUTER);
    system(sysevent_cmd);
	syscfg_get(NULL, "MoCA_previous_status", MocaPreviousStatus, sizeof(MocaPreviousStatus));
	prev = atoi(MocaPreviousStatus);
	if(prev == 1)
	{
		system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool true");
	}
	else
	{
		system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool false");
	}

    system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool true");
    
    system("sysevent set forwarding-restart");
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
    system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string bridge-static");

    printf("******************************");
    printf("* Disabled (after cfg file)  *");
    printf("******************************");
}

static void GWP_EnterBridgeMode(void)
{
    //GWP_UpdateEsafeAdminMode(DOCESAFE_ENABLE_DISABLE);
    //DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_DISABLED);
    /* Reset Switch, to remove all VLANs */ 
    // GSWT_ResetSwitch();
    //DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_NOT_INITIATED);
    char sysevent_cmd[80];
	char MocaStatus[16] = {0};

	syscfg_get(NULL, "MoCA_current_status", MocaStatus, sizeof(MocaStatus));

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
	system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool false");
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", active_mode);
    system(sysevent_cmd);
    system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool false");
    
    system("sysevent set forwarding-restart");
}

static void GWP_EnterPseudoBridgeMode(void)
{
        if (eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
        return;
    
//     GWP_UpdateEsafeAdminMode(eRouterMode);
//     DOCSIS_ESAFE_SetErouterOperMode(DOCESAFE_EROUTER_OPER_NOIPV4_NOIPV6);
//     DOCSIS_ESAFE_SetEsafeProvisioningStatusProgress(DOCSIS_EROUTER_INTERFACE, ESAFE_PROV_STATE_IN_PROGRESS);
    char sysevent_cmd[80];
    char MocaStatus[16] = {0};

	syscfg_get(NULL, "MoCA_current_status", MocaStatus, sizeof(MocaStatus));

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
	
	system("ccsp_bus_client_tool eRT setv Device.MoCA.Interface.1.Enable bool false");	
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", BRMODE_PRIMARY_BRIDGE);
    system(sysevent_cmd);
    system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.ErouterEnable bool false");
    system("sysevent set forwarding-restart");
}

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
            system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string bridge-static");
            
            GWP_DisableERouter();
            
            GWP_SysCfgSetInt("last_erouter_mode", eRouterMode);  // save the new mode only
            syscfg_commit();
        }
        else
        {
            GWP_SysCfgSetInt("last_erouter_mode", eRouterMode);  // save the new mode only
            syscfg_commit();
            // TLV202 allows eRouter, but we still need to check user's preference
            //bridge_mode = GWP_SysCfgGetInt("bridge_mode");
            //if (bridge_mode == 1 || bridge_mode == 2)
            //{
                // erouter disabled by user, keep it disabled
                //mipieper -- dont disable erouter on bridge mode 
                //eRouterMode = DOCESAFE_ENABLE_DISABLE;
            //}
            /*else*/ if (oldRouterMode == DOCESAFE_ENABLE_DISABLE_extIf) // from disable to enable
            {
                webui_started = 0;
                active_mode = BRMODE_ROUTER; //This is set so that the callback from LanMode does not trigger another transition.
                                                    //The code here will here will handle it.
                system("ccsp_bus_client_tool eRT setv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode string router");
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
                system("sysevent set erouter_mode-updated");
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

    if (oldActiveMode == active_mode) return; // Exit if no transition
    
    webui_started = 0;
    switch ( active_mode) {
     
        case BRMODE_ROUTER:
            if (oldActiveMode == BRMODE_GLOBAL_BRIDGE) {
                GWP_EnableERouter();
            } else {
                GWP_EnterRouterMode();
            }
            break;
        case BRMODE_GLOBAL_BRIDGE:
            GWP_DisableERouter();
            break;
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

    printf("******************************");
    printf("*        IPv4 Routing        *");
    printf("******************************");

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


    printf("******************************");
    printf("*        IPv6 Routing        *");
    printf("******************************");

    return 0;
}
#endif

static void check_lan_wan_ready()
{
	char br_st[16];
	char lan_st[16];
	char wan_st[16];
	char ipv6_prefix[128];

		
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "bridge-status", br_st, sizeof(br_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "lan-status", lan_st, sizeof(lan_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "wan-status", wan_st, sizeof(wan_st));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "ipv6_prefix", ipv6_prefix, sizeof(ipv6_prefix));

	printf("****************************************************\n");
	printf("       %s   %s   %s   %s  %d  %d                    \n", br_st, lan_st, wan_st, ipv6_prefix, eRouterMode, bridge_mode);
	printf("****************************************************\n");

	
	if (bridge_mode != 0 || eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf)
	{
		if (!strcmp(br_st, "started"))
		{
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
			once = 1;
		}
	}
	else
	{
		if (eRouterMode == DOCESAFE_ENABLE_IPv4_extIf)
		{
			if (!strcmp(lan_st, "started") && !strcmp(wan_st, "started"))
			{
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				once = 1;
			}
		}
		else if (eRouterMode == DOCESAFE_ENABLE_IPv4_IPv6_extIf)
		{
			if (!strcmp(lan_st, "started") && (!strcmp(wan_st, "started")) && strlen(ipv6_prefix))
			{
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				once = 1;
			}
		}
		else if (eRouterMode == DOCESAFE_ENABLE_IPv6_extIf)
		{
			if (!strcmp(lan_st, "started") && strlen(ipv6_prefix))
			{
				sysevent_set(sysevent_fd_gs, sysevent_token_gs, "start-misc", "ready", 0);
				once = 1;
			}
		}
	}
}

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
    async_id_t ipv6_dhcp_asyncid;
    async_id_t wan_status_asyncid;
    async_id_t ipv6_prefix_asyncid;
    async_id_t pnm_asyncid;

    char buf[10];
	time_t time_now = { 0 }, time_before = { 0 };
    
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

    sysevent_set_options(sysevent_fd, sysevent_token, "system-restart", TUPLE_FLAG_EVENT);
    GWPROV_PRINT(" Set notifications done \n");    
//     sysevent_get(sysevent_fd, sysevent_token, "homesecurity_lan_l3net", buf, sizeof(buf));
//     if (buf[0] != '\0' && atoi(buf))
//         netids_inited = 1;
//     
//     sysevent_get(sysevent_fd, sysevent_token, "snmp_subagent-status", buf, sizeof(buf));
//     if (buf[0] != '\0' && strcmp("started",buf)==0 )
//         snmp_inited = 1;
//     
//     if(netids_inited && snmp_inited && !factory_mode) {
//         LAN_start();
//     }

    for (;;)
    {
        char name[25], val[42], buf[10];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_asyncid;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if (err)
        {
		  /* 
		     * Log should come for every 1hour 
		     * - time_now = getting current time 
		     * - difference between time now and previous time is greater than 
		     *    3600 seconds
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
            if (strcmp(name, "erouter_mode")==0)
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
                system("reboot"); // Reboot on change of device mode.
            }
            else if (strcmp(name, "ipv4-status") == 0)
            {
                if (strcmp(val, "up")==0)
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv4Up();
#endif
                }
                else if (strcmp(val, "down")==0)
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv4Down();
#endif
                }
            }
            else if (strcmp(name, "ipv6-status") == 0)
            {
                if (strcmp(val, "up")==0)
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv6Up();
#endif
                }
                else if (strcmp(val, "down")==0)
                {
#if !defined(_PLATFORM_RASPBERRYPI_)
                    GWP_ProcessIpv6Down();
#endif
                }
            }
            else if (strcmp(name, "system-restart") == 0)
            {
                printf("gw_prov_sm: got system restart\n");
                GWP_ProcessUtopiaRestart();
            }
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
            else if (strcmp(name, "bring-lan") == 0)
#else
            else if (strcmp(name, "pnm-status") == 0)
#endif 
            {
		 GWPROV_PRINT(" bring-lan/pnm-status received \n");                
                pnm_inited = 1;
                if (netids_inited) {
                        LAN_start();
                }
            }
            /*else if (strcmp(name, "snmp_subagent-status") == 0 && !snmp_inited)
            {
                snmp_inited = 1;
                if (netids_inited) {
                    if(!factory_mode)
                        LAN_start();
                }
            }*/ 
            else if (strcmp(name, "primary_lan_l3net") == 0)
            {
		 GWPROV_PRINT(" primary_lan_l3net received \n");              
                if (pnm_inited)
                 {
                    LAN_start();
                 }
                netids_inited = 1;
            }
            else if (strcmp(name, "lan-status") == 0 || strcmp(name, "bridge-status") == 0 ) 
            {
                if (strcmp(val, "started") == 0) {
                    if (!webui_started) { 
#if defined(_PLATFORM_RASPBERRYPI_)
                        system("/bin/sh /etc/webgui.sh");
#else
                        startWebUIProcess();
#endif
                        webui_started = 1 ;
#ifdef CONFIG_CISCO_HOME_SECURITY
                        //Piggy back off the webui start event to signal XHS startup
                        sysevent_get(sysevent_fd_gs, sysevent_token_gs, "homesecurity_lan_l3net", buf, sizeof(buf));
                        if (buf[0] != '\0') sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv4-up", buf, 0);
#endif
                    }
                   
                    if (!hotspot_started) {
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
                        printf("Not Calling hotspot-start for XB3 it will be done in cosa_start_rem.sh\n");
#else
                        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "hotspot-start", "", 0);
                        hotspot_started = 1 ;
#endif
                    } 
                    
                    if (factory_mode && lan_telnet_started == 0) {
                        system("/usr/sbin/telnetd -l /usr/sbin/cli -i brlan0");
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
                }
            } else if (strcmp(name, "tr_" ER_NETDEVNAME "_dhcpv6_client_v6addr") == 0) {
                Uint8 v6addr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ];
                Uint8 soladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ];
                inet_pton(AF_INET6, val, v6addr);
#if !defined(_PLATFORM_RASPBERRYPI_)
                getMultiCastGroupAddress(v6addr,soladdr);
#endif
                inet_ntop(AF_INET6, soladdr, val, sizeof(val));
                
                
                sysevent_set(sysevent_fd_gs, sysevent_token_gs, "ipv6_"ER_NETDEVNAME"_dhcp_solicNodeAddr", val,0);

                unsigned char lan_wan_ready = 0;
                char command[256], result_buf[32];
                command[0] = result_buf[0] = '\0';

                sysevent_get(sysevent_fd_gs, sysevent_token_gs, "start-misc", result_buf, sizeof(result_buf));
                lan_wan_ready = strstr(result_buf, "ready") == NULL ? 0 : 1;

                if(!lan_wan_ready) {
                    snprintf(command, sizeof(command),"ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", ER_NETDEVNAME, val);
                    system(command);
                }
                else
                    sysevent_set(sysevent_fd_gs, sysevent_token_gs, "firewall-restart", "",0);
            }
			else if (!strcmp(name, "wan-status") && !strcmp(val, "started")) {
				if (!once) {
						check_lan_wan_ready();
					}
			}
			else if (!strcmp(name, "ipv6_prefix") && strlen(val) > 5)
				if (!once) {
						check_lan_wan_ready();
					}
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
    system("sysevent set phylink_wan_state down");
   
    printf("\n**************************\n");
    printf("\nsysevent set phylink_wan_state down\n");
    printf("\n**************************\n\n");
    return 0;
}

static int GWP_act_DocsisLinkDown_callback_2()
{
    
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf)
    {
       printf("Stopping wan service\n");
       system("sysevent set wan-stop");
   #ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
       system("sysevent set dhcpv6_client-stop");
   #endif
    }

    return 0;
}


static int GWP_act_DocsisLinkUp_callback()
{
    phylink_wan_state = 1;
    system("sysevent set phylink_wan_state up");
    printf("\n**************************\n");
    printf("\nsysevent set phylink_wan_state up\n");
    printf("\n**************************\n\n");

    
#if defined(_PLATFORM_RASPBERRYPI_)
     char *temp;
     char command[128];
     char wanPhyName[20];
     char out_value[20];
     int outbufsz = sizeof(out_value);

    char* buff = NULL;
    buff = malloc(sizeof(char)*50);
    if(buff == NULL)
    {
        return -1;
    }

    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
        strcpy(wanPhyName, out_value);
        printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
        if(buff != NULL)
            free(buff);
        return -1;
    }
    snprintf(command,sizeof(command),"ifconfig %s | grep \"inet addr\" | cut -d':' -f2 | awk '{print$1}'", wanPhyName);

    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf /*&& bridge_mode == 0*/) // mipieper - pseduo bridge support
    {
        printf("Starting wan service\n");
        system("sysevent set wan-start");
        sleep(50);
        system("sysevent set current_ipv4_link_state up");
        system("sysevent set ipv4_wan_ipaddr `ifconfig erouter0 | grep \"inet addr\" | cut -d':' -f2 | awk '{print$1}'`");
        system("sysevent set ipv4_wan_subnet `ifconfig erouter0 | grep \"inet addr\" | cut -d':' -f4 | awk '{print$1}'`");
        system("sysevent set wan_service-status started");
        system("sysevent set bridge_mode `syscfg get bridge_mode`");
    }
    if(buff != NULL)
        free(buff);
#else
    if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf /*&& bridge_mode == 0*/) // mipieper - pseduo bridge support
    {
        printf("Starting wan service\n");
        system("sysevent set wan-start");
    #ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
        system("sysevent set dhcpv6_client-start");
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
    char command[50] = {0};
    char wanPhyName[20] = {0};
    char out_value[20] = {0};
    int outbufsz = sizeof(out_value);

    char* buff = NULL;
    buff = malloc(sizeof(char)*50);
    if(buff == NULL)
    {
        return -1;
    }
    char previousLinkStatus[10] = "down";
    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
        strcpy(wanPhyName, out_value);
        printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
        if(buff != NULL)
            free(buff);
        return -1;
    }
    sprintf(command, "cat /sys/class/net/%s/operstate", wanPhyName);

    while(1)
    {
        FILE *fp;
        memset(buff,0,sizeof(buff));

        /* Open the command for reading. */
        fp = popen(command, "r");
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
        pclose(fp);
        if(!strcmp(buff, (const char *)previousLinkStatus))
        {
            /*printf("Link status not changed\n");*/
        }
        else
        {
            if(!strcmp(buff, "up"))
            {
                /*printf("Ethernet status :%s\n", buff);*/
                GWP_act_DocsisLinkUp_callback();
            }
            else if(!strcmp(buff, "down"))
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
            memset(previousLinkStatus,0,sizeof(previousLinkStatus));
            strcpy((char *)previousLinkStatus, buff);
            /*printf("Previous Ethernet status :%s\n", (char *)previousLinkStatus);*/
        }
        sleep(5);
    }
    if(buff != NULL)
        free(buff);

    return 0;
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
    //TlvParseStatus_e tlvStatus;
    TlvParsingStatusExtIf_e tlvStatus;

    
    if( cfgFile != NULL)
    {
      cfgFileName = cfgFile;
      printf("Got CfgFile \"%s\"", cfgFileName);
    }
    else
    {
       goto gimReply;
    }

    char cmd[80];
    sprintf(cmd, "sysevent set docsis_cfg_file %s", cfgFileName);
    system(cmd);

    printf("sysevent set docsis_cfg_file %s\n", cfgFileName);

    if (stat(cfgFileName, &cfgFileStat) != 0)
    {
        printf("Cannot stat eSafe Config file \"%s\", %s, aborting Config file", cfgFileName, strerror(errno));
        goto gimReply;
    }
    cfgFileBuffLen = cfgFileStat.st_size;
    if (cfgFileBuffLen == 0)
    {
        /* No eSafe TLVs --> No eRouter TLVs */
        printf("CfgFile \"%s\" is empty", cfgFileName);
        goto gimReply;
    }

    cfgFileBuff = malloc(cfgFileBuffLen);
    if (cfgFileBuff == NULL)
    {
        printf("Cannot alloc buffer for eSafe Config file \"%s\", aborting Config file", cfgFileName, strerror(errno));
        goto gimReply;
    }

    if ((cfgFd = open(cfgFileName, O_RDONLY)) < 0)
    {
        printf("Cannot open eSafe Config file \"%s\", %s, aborting Config file", cfgFileName, strerror(errno));
        goto freeMem;
    }

    if ((actualNumBytes = read(cfgFd, cfgFileBuff, cfgFileBuffLen)) < 0)
    {
        printf("Cannot read eSafe Config file \"%s\", %s, aborting Config file", cfgFileName, strerror(errno));
        goto closeFile;
    }
    else if (actualNumBytes != cfgFileBuffLen)
    {
        printf("eSafe Config file \"%s\", actual len (%d) different than stat (%d), aborting Config file", cfgFileName, actualNumBytes, cfgFileBuffLen);
        goto closeFile;
    }

    oldRouterMode = eRouterMode;

    
    tlvStatus = parseTlv(cfgFileBuff, cfgFileBuffLen);

    if (tlvStatus != TLV_OK_extIf)
    {
        printf("eSafe Config file \"%s\", parsing error (%d), aborting Config file", cfgFileName, tlvStatus);
        goto closeFile;
    }

    printf("eSafe Config file \"%s\", parsed completed, status %d\n", cfgFileName, tlvStatus);

    //GW_UpdateTr069Cfg();

    GWP_UpdateERouterMode();

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
    Char *cmdline;

    /* Update esafe db with router provisioning status*/
    
    eSafeDevice_SetProvisioningStatusProgress(ESAFE_PROV_STATE_IN_PROGRESS_extIf);
	
    printf("Starting ActiveUnprovisioned processes");

    /* Add paths for eRouter dev counters */
    printf("Adding PP paths");
    cmdline = "add "IFNAME_ETH_0" cni0 " ER_NETDEVNAME " in";
    COMMONUTILS_file_write("/proc/net/ti_pp_path", cmdline, strlen(cmdline));
    cmdline = "add cni0 "IFNAME_ETH_0" " ER_NETDEVNAME " out";
    COMMONUTILS_file_write("/proc/net/ti_pp_path", cmdline, strlen(cmdline));

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

    printf("******************************");
    printf("* Disabled (before cfg file) *");
    printf("******************************");

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
    char macstr[20];
    Uint8 lladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ];
    Uint8 soladdr[ NETUTILS_IPv6_GLOBAL_ADDR_LEN / sizeof(Uint8) ];
    char soladdrKey[64];
    char soladdrStr[64];
    int sysevent_bridge_mode = 0;

#if !defined(_PLATFORM_RASPBERRYPI_)
    /* Docsis initialized */
    printf("Got DOCSIS Initialized");

    // printf("Utopia init done\n");
    printf("Loading erouter0 network interface driver\n");
    system("insmod " ERNETDEV_MODULE " netdevname=" ER_NETDEVNAME);

    {
        macaddr_t macAddr;
        
        getWanMacAddress(&macAddr);
       
       setNetworkDeviceMacAddress(ER_NETDEVNAME,&macAddr);
    }  

    
    getDocsisDbFactoryMode(&factory_mode);
#endif

    if (factory_mode) {
        //GWP_SysCfgSetInt("bridge_mode", 2);
        GWP_SysCfgSetInt("mgmt_lan_telnetaccess", 1);
        //GWP_SysCfgSetInt("last_erouter_mode", 0);
     }

//     mipieper - remove for pseudo bridge support. Could add back depending on policy. 
//     if (bridge_mode == 0)
//     {
//
//         bridge_mode = eRouterMode == DOCESAFE_ENABLE_DISABLE_extIf ? 2 : 0;
//     }
#if !defined(INTEL_PUMA7) && !defined(_COSA_BCM_MIPS_) && !defined(_COSA_BCM_ARM_)
	printf("Not Initializing bridge_mode and eRouterMode for XB3\n");
#else
    bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;
    char sysevent_cmd[80];
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", sysevent_bridge_mode);
    system(sysevent_cmd);
#endif
  
#if !defined(_PLATFORM_RASPBERRYPI_)
    GWP_DocsisInited();
#endif
  
      system("sysevent set docsis-initialized 1");
#if !defined(_PLATFORM_RASPBERRYPI_)

    /* Must set the ESAFE Enable state before replying to the DocsisInit event */
    eRouterModeTmp = eRouterMode;
//      mipieper - remove for pseudo bridge support. Partial bridge should not force global bridge.
//     if(bridge_mode == 2) 
//         eRouterModeTmp = DOCESAFE_ENABLE_DISABLE;
    GWP_UpdateEsafeAdminMode(eRouterModeTmp);

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
    
    eSafeDevice_SetErouterOperationMode(operMode);

  
   	eSafeDevice_SetServiceIntImpact();

    /* Disconnect docsis LB */
    printf("Disconnecting DOCSIS local bridge");
   
    connectLocalBridge(False);

    /* This is an SRN, reply */
    printf("Got Docsis INIT - replying");
   
    notifyDocsisInitializedResponse();

    
    //calcualte erouter base solicited node address
   
    getInterfaceLinkLocalAddress(ER_NETDEVNAME, lladdr);
    
    getMultiCastGroupAddress(lladdr,soladdr);
#endif

    snprintf(soladdrKey, sizeof(soladdrKey), "ipv6_%s_ll_solicNodeAddr", ER_NETDEVNAME);
    inet_ntop(AF_INET6, soladdr, soladdrStr, sizeof(soladdrStr));
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, soladdrKey, soladdrStr,0);

    unsigned char lan_wan_ready = 0;
    char command[256], result_buf[32];
    command[0] = result_buf[0] = '\0';

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, "start-misc", result_buf, sizeof(result_buf));
    lan_wan_ready = strstr(result_buf, "ready") == NULL ? 0 : 1;

    if(!lan_wan_ready) {
        snprintf(command, sizeof(command),"ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", ER_NETDEVNAME, soladdrStr);
        system(command);
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
        snprintf(command, sizeof(command),"ip6tables -t mangle -I PREROUTING 1 -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT", IFNAME_WAN_0, soladdrStr);
        system(command);
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
    int i;
#if !defined(_PLATFORM_RASPBERRYPI_)
	int sysevent_bridge_mode = 0;
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);
    //system("sysevent set lan-start");
   
/* TODO: OEM to implement swctl apis */

    /* Register on docsis Init event */
    GWPROV_PRINT(" registerDocsisInitEvents \n");    
    registerDocsisInitEvents(); 
    GWPROV_PRINT(" Calling /etc/utopia/utopia_init.sh \n"); 
    system("/etc/utopia/utopia_init.sh");

    syscfg_init();
#else
    system("mkdir -p /nvram");
    system("rm -f /nvram/dnsmasq.leases");
    system("syslogd -f /etc/syslog.conf");

    //copy files that are needed by CCSP modules
    system("cp /usr/ccsp/ccsp_msg.cfg /tmp");
    system("touch /tmp/cp_subsys_ert");

    /* Below link is created because crond is expecting /crontabs/ dir instead of /var/spool/cron/crontabs */
    system("ln -s /var/spool/cron/crontabs /");
    /* directory /var/run/firewall because crond is expecting this dir to execute time specific blocking of firewall*/
    system("mkdir -p /var/run/firewall");

    system("/etc/utopia/utopia_init.sh");

    syscfg_init();

    sleep(2);

    char command[50];
    char wanPhyName[20];
    char out_value[20];
    int outbufsz = sizeof(out_value);

    char previousLinkStatus[10] = "down";
    if (!syscfg_get(NULL, "wan_physical_ifname", out_value, outbufsz))
    {
       strcpy(wanPhyName, out_value);
       printf("wanPhyName = %s\n", wanPhyName);
    }
    else
    {
       return -1;
    }

    system("ifconfig eth0 down");
    memset(command,0,sizeof(command));
    sprintf(command, "ip link set eth0 name %s", wanPhyName);
    printf("****************value of command = %s**********************\n", command);
    system(command);

    memset(command,0,sizeof(command));
    sprintf(command, "ifconfig %s up", wanPhyName);
    printf("************************value of command = %s\***********************n", command);
    system(command);
#endif

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov", &sysevent_token);

    if (sysevent_fd >= 0)
    {
        system("sysevent set phylink_wan_state down");
        GWPROV_PRINT(" Creating Thread  GWP_sysevent_threadfunc \n"); 
        pthread_create(&sysevent_tid, NULL, GWP_sysevent_threadfunc, NULL);
    }
    
    //Make another connection for gets/sets
    sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gw_prov-gs", &sysevent_token_gs);

#if !defined(_PLATFORM_RASPBERRYPI_)
    /*if (eRouterMode != DOCESAFE_ENABLE_DISABLE_extIf)
    {
        printf("Utopia init done, starting lan\n");
        system("sysevent set lan-start");
    }*/

    printf("Waiting for Docsis INIT\n");

	bridge_mode = GWP_SysCfgGetInt("bridge_mode");
    eRouterMode = GWP_SysCfgGetInt("last_erouter_mode");
    
    sysevent_bridge_mode = getSyseventBridgeMode(eRouterMode, bridge_mode);
    active_mode = sysevent_bridge_mode;

	char sysevent_cmd[80];
    snprintf(sysevent_cmd, sizeof(sysevent_cmd), "sysevent set bridge_mode %d", sysevent_bridge_mode);
    system(sysevent_cmd);

    /* Now that we have the ICC que (SME) and we are registered on the docsis INIT    */
    /* event, we can notify PCD to continue                                           */
    sendProcessReadySignal();
#endif

    /* Initialize Switch */
    // VEN_SWT_InitSwitch();

#if defined(_PLATFORM_RASPBERRYPI_)
    printf("Thread to monitor link status \n");
    pthread_create(&linkstate_tid, NULL, GWP_linkstate_threadfunc, NULL);
#endif

    return 0;
}

#if !defined(_PLATFORM_RASPBERRYPI_)
static int GWP_act_DocsisTftpOk_callback(){
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
    int i;
    char buf[10];
    GWPROV_PRINT(" Entry %s \n", __FUNCTION__);      
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
    printf("Started gw_prov_utopia");

#if !defined(_PLATFORM_RASPBERRYPI_)
#ifdef FEATURE_SUPPORT_RDKLOG
       setenv("LOG4C_RCPATH","/rdklogger",1);
       rdk_logger_init(DEBUG_INI_NAME);
    #endif

    GWPROV_PRINT(" Entry gw_prov_utopia\n");
    if( findProcessId(argv[0]) > 0 )
    {
        printf("Already running");
        GWPROV_PRINT(" gw_prov_utopia already running. Returning...\n");
        return 1;
    }

    printf("Register exception handlers");
    
    registerProcessExceptionHandlers(argv[0]);

    GWP_InitDB();

    appCallBack *obj = NULL;
    obj = (appCallBack*)malloc(sizeof(appCallBack));
	
    obj->pGWP_act_DocsisLinkDown_1 =  GWP_act_DocsisLinkDown_callback_1;
    obj->pGWP_act_DocsisLinkDown_2 =  GWP_act_DocsisLinkDown_callback_2;
    obj->pGWP_act_DocsisLinkUp = GWP_act_DocsisLinkUp_callback;
    obj->pGWP_act_DocsisCfgfile = GWP_act_DocsisCfgfile_callback;
    obj->pGWP_act_DocsisTftpOk = GWP_act_DocsisTftpOk_callback;
    obj->pGWP_act_BefCfgfileEntry = GWP_act_BefCfgfileEntry_callback;
    obj->pGWP_act_DocsisInited = GWP_act_DocsisInited_callback;
    obj->pGWP_act_ProvEntry = GWP_act_ProvEntry_callback;
    obj->pDocsis_gotEnable = docsis_gotEnable_callback;
    obj->pGW_Tr069PaSubTLVParse = GW_Tr069PaSubTLVParse;
#ifdef CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION
    obj->pGW_SetTopologyMode = GW_setTopologyMode;
#endif
    GWPROV_PRINT(" Creating Event Handler\n");
    /* Command line - ignored */
    SME_CreateEventHandler(obj);
    GWPROV_PRINT(" Creating Event Handler over\n");

#else
    GWP_act_ProvEntry_callback();
    GWP_act_DocsisInited_callback();

    (void) pthread_join(sysevent_tid, NULL);
    (void) pthread_join(linkstate_tid, NULL);
#endif
    return 0;
}



