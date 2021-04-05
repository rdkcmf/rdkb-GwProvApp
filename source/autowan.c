#ifdef AUTOWAN_ENABLE
#include <stdio.h>

#include <string.h>
#include<unistd.h> 
#include<stdint.h>
#include<errno.h> 
#include <stdlib.h>
#include<sys/types.h> 
#include<sys/stat.h> 
#include<fcntl.h> 
#include "autowan.h"
#include "gw_prov_sm.h"
#include "cm_hal.h"
#include "ccsp_hal_ethsw.h"
#if defined (_MACSEC_SUPPORT_)
#include <platform_hal.h>
#endif
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#ifdef FEATURE_SUPPORT_RDKLOG
#include "rdk_debug.h"
#endif


//#define _SIMULATE_PC_
#define BOOL char
#define AUTO_WAN_LOG GWPROV_PRINT
#define WAN_MODE_AUTO		0
#define WAN_MODE_ETH		1
#define WAN_MODE_DOCSIS		2
#define WAN_MODE_UNKNOWN	3

#define AUTOWAN_RETRY_CNT	3
#define AUTOWAN_RETRY_INTERVAL	80 /* TBD */
#define MAC_ADDR_LEN    6
typedef struct mac_addr
{
    uint8_t hw[ MAC_ADDR_LEN ];
} macaddr_t;

#if defined (_MACSEC_SUPPORT_)
#define MACSEC_TIMEOUT_SEC    10
#endif

#define ERT_MODE_IPV4           1
#define ERT_MODE_IPV6           2
#define ERT_MODE_DUAL           3

#if defined(INTEL_PUMA7)
#define ESAFE_CFG_FILE          "/var/tmp/eSafeCfgFile.downloaded"
#endif

int g_CurrentWanMode        = 0;
int g_LastKnowWanMode       = 0;
int g_SelectedWanMode       = 0;
int g_AutoWanRetryCnt       = 0;
int g_AutoWanRetryInterval  = 0;

#if defined (_BRIDGE_UTILS_BIN_)
    int g_OvsEnable             = 0;
#endif
void IntializeAutoWanConfig();
int GetCurrentWanMode();
int GetSelectedWanMode();
int GetLastKnownWanMode();
void CheckAltWan();
void CheckWanModeLocked();
void WanMngrThread();
void SelectedWanMode(int mode);
void SetLastKnownWanMode(int mode);
void HandleAutoWanMode(void);
void ManageWanModes(int mode);
int TryAltWan(int *mode);
int CheckWanStatus();
int CheckWanConnection(int mode);
void RevertTriedConfig(int mode);
void AutoWan_BkupAndReboot();
int CheckEthWanLinkStatus();
int CheckEthWanLinkStatus()
{
    CCSP_HAL_ETHSW_PORT         port;
    INT                         status;
    CCSP_HAL_ETHSW_LINK_RATE    LinkRate;
    CCSP_HAL_ETHSW_DUPLEX_MODE  DuplexMode;
    CCSP_HAL_ETHSW_LINK_STATUS  LinkStatus;

    /* Use Hard coded values as EthWan_getEthWanPort() HAL may not be set correctly in all devices as RDKB calls this in GwProvApp-EthWan & CosaDmlEthWanSetEnable() */
    port = ETHWAN_DEF_INTF_NUM;

    port += CCSP_HAL_ETHSW_EthPort1; /* ETH WAN HALs start from 0 but Ethernet Switch HALs start with 1*/

    status = CcspHalEthSwGetPortStatus(port, &LinkRate, &DuplexMode, &LinkStatus);

    if ( status == RETURN_OK )
    {
       return LinkStatus;
    }
    return 1;
}
int
CosaDmlEthWanSetEnable
    (
        BOOL                       bEnable
    );

char* WanModeStr(int WanMode)
{
    if(WanMode == WAN_MODE_AUTO)
    {
         return "WAN_MODE_AUTO";
    }
    if(WanMode == WAN_MODE_ETH)
    {
         return "WAN_MODE_ETH";
    }
    if(WanMode == WAN_MODE_DOCSIS)
    {
         return "WAN_MODE_DOCSIS";
    }
    if(WanMode == WAN_MODE_UNKNOWN)
    {
         return "WAN_MODE_UNKNOWN";
    }
}
void LogWanModeInfo()
{
    AUTO_WAN_LOG("CurrentWanMode  - %s\n",WanModeStr(g_CurrentWanMode));
    AUTO_WAN_LOG("SelectedWanMode - %s\n",WanModeStr(g_SelectedWanMode));
    AUTO_WAN_LOG("LastKnowWanMode - %s\n",WanModeStr(g_LastKnowWanMode));
}

void AutoWAN_main()
{
    int thread_status = 0;
    static pthread_t AutoWAN_tid;
    IntializeAutoWanConfig();
#if defined (_BRIDGE_UTILS_BIN_)
    char buf[ 8 ] = { 0 };
    if( 0 == syscfg_get( NULL, "mesh_ovs_enable", buf, sizeof( buf ) ) )
    {
          if ( strcmp (buf,"true") == 0 )
            g_OvsEnable = 1;
          else 
            g_OvsEnable = 0;

    }
    else
    {
          AUTO_WAN_LOG("syscfg_get failed to retrieve ovs_enable\n");

    }
#endif 
    thread_status = pthread_create(&AutoWAN_tid, NULL, WanMngrThread, NULL);
        if (thread_status == 0)
        {
            AUTO_WAN_LOG("WanMngrThread thread created successfully\n");
        }
        else
        {
            AUTO_WAN_LOG("%s error occured while creating WanMngrThread thread\n", strerror(errno));
            
        }
    //WanMngrThread();
}


void IntializeAutoWanConfig()
{
    AUTO_WAN_LOG("%s\n",__FUNCTION__);
    g_CurrentWanMode        = WAN_MODE_UNKNOWN;
    g_LastKnowWanMode       = WAN_MODE_DOCSIS;
    g_SelectedWanMode       = WAN_MODE_AUTO;
    g_AutoWanRetryCnt       = AUTOWAN_RETRY_CNT;
    g_AutoWanRetryInterval  = AUTOWAN_RETRY_INTERVAL;

    char out_value[20];
    int outbufsz = sizeof(out_value);
    memset(out_value,0,sizeof(out_value));
    if (!syscfg_get(NULL, "selected_wan_mode", out_value, outbufsz))
    {
       g_SelectedWanMode = atoi(out_value);
       AUTO_WAN_LOG("AUTOWAN %s Selected WAN mode = %s\n",__FUNCTION__,WanModeStr(g_SelectedWanMode));
    }
    else
    {
       SelectedWanMode(WAN_MODE_DOCSIS);
       AUTO_WAN_LOG("AUTOWAN %s AutoWAN is not Enabled, Selected WAN mode - %s\n",__FUNCTION__, WanModeStr(g_SelectedWanMode));
    }
    SetCurrentWanMode(WAN_MODE_UNKNOWN);
    LogWanModeInfo();

}

int GetCurrentWanMode()
{
    return g_CurrentWanMode;
}

void SetCurrentWanMode(int mode)
{
    char buf[8];
    memset(buf, 0, sizeof(buf));
    g_CurrentWanMode = mode;
    AUTO_WAN_LOG("%s Set Current WanMode = %s\n",__FUNCTION__, WanModeStr(g_CurrentWanMode)); 
    snprintf(buf, sizeof(buf), "%d", g_CurrentWanMode);
    if (syscfg_set(NULL, "curr_wan_mode", buf) != 0)
    {
            AUTO_WAN_LOG("syscfg_set failed for curr_wan_mode\n");
    }
    else
    {
            if (syscfg_commit() != 0)
            {
                AUTO_WAN_LOG("syscfg_commit failed for curr_wan_mode\n");
            }

    }
}

int GetSelectedWanMode()
{
    return g_SelectedWanMode;
}

void SelectedWanMode(int mode)
{
    char buf[8];
    g_SelectedWanMode = mode;
    AUTO_WAN_LOG("%s Set  SelectedWanMode = %s\n",__FUNCTION__, WanModeStr(g_SelectedWanMode));
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%d", mode);
        if (syscfg_set(NULL, "selected_wan_mode", buf) != 0)
        {
            AUTO_WAN_LOG("syscfg_set failed for curr_wan_mode\n");
        }
        else
        {
            if (syscfg_commit() != 0)
            {
                AUTO_WAN_LOG("syscfg_commit failed for curr_wan_mode\n");
            }

        }
}

int GetLastKnownWanMode()
{
    return g_LastKnowWanMode;
}

void SetLastKnownWanMode(int mode)
{
    char buf[8];
    g_LastKnowWanMode = mode;
    AUTO_WAN_LOG("%s Set Last Known WanMode = %s\n",__FUNCTION__, WanModeStr(g_LastKnowWanMode));
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "%d", mode);
        if (syscfg_set(NULL, "last_wan_mode", buf) != 0)
        {
            AUTO_WAN_LOG("syscfg_set failed for last_wan_mode\n");
        }
        else
        {
            if (syscfg_commit() != 0)
            {
                AUTO_WAN_LOG("syscfg_commit failed for last_wan_mode\n");
            }

        } 
}

void WanMngrThread()
{
    AUTO_WAN_LOG("%s\n",__FUNCTION__);
    pthread_detach(pthread_self());
    AUTO_WAN_LOG("%s Check if AutoWan is Enabled\n",__FUNCTION__);
    switch (GetSelectedWanMode()) 
    { 
       case WAN_MODE_AUTO:
        AUTO_WAN_LOG("Auto WAN Mode is enabled, try Last known WAN mode\n");
        HandleAutoWanMode();
        break;
 
       case WAN_MODE_ETH:
        AUTO_WAN_LOG("Booting-Up in SelectedWanMode - %s\n",WanModeStr(GetSelectedWanMode()));
        SetLastKnownWanMode(WAN_MODE_ETH);
        SetCurrentWanMode(WAN_MODE_ETH);
#if defined(INTEL_PUMA7)
        system("cmctl down");
#endif
#ifdef _SIMULATE_PC_
        system("killall udhcpc");
        system("udhcpc -i eth1 &");
#endif
        break;
 
       case WAN_MODE_DOCSIS:
        AUTO_WAN_LOG("Booting-Up in SelectedWanMode - %s\n",WanModeStr(GetSelectedWanMode())); 
        SetLastKnownWanMode(WAN_MODE_DOCSIS);
        SetCurrentWanMode(WAN_MODE_DOCSIS);
        #ifdef _SIMULATE_PC_
        system("killall udhcpc");
        system("udhcpc -i eth2 &");
        #endif
        break;
 
       default: AUTO_WAN_LOG("This is not expected, setting WAN mode to Auto\n");
        SelectedWanMode(WAN_MODE_AUTO);
        HandleAutoWanMode();
        break;   
    } 

}

void HandleAutoWanMode(void)
{
    AUTO_WAN_LOG("%s\n",__FUNCTION__);
    if(WAN_MODE_UNKNOWN == GetLastKnownWanMode())
    {
        AUTO_WAN_LOG("Last known WAN mode is Unknown\n");   
    }
    switch (GetLastKnownWanMode()) 
    { 
       case WAN_MODE_ETH:
        AUTO_WAN_LOG("Booting-Up in Last known WanMode - %s\n",WanModeStr(GetLastKnownWanMode()));
#ifdef _SIMULATE_PC_
        system("killall udhcpc");
        system("udhcpc -i eth1 &");
#endif
        ManageWanModes(WAN_MODE_ETH);
        break;
 
       case WAN_MODE_DOCSIS:
        AUTO_WAN_LOG("Booting-Up in Last known WanMode - %s\n",WanModeStr(GetLastKnownWanMode()));
#ifdef _SIMULATE_PC_
        system("killall udhcpc");
        system("udhcpc -i eth2 &");
#endif
        { 
                ManageWanModes(WAN_MODE_DOCSIS);
        } 
        break;

       case WAN_MODE_UNKNOWN:
        AUTO_WAN_LOG("Booting-Up in Last known WanMode - %s\n",WanModeStr(GetLastKnownWanMode()));
#ifdef _SIMULATE_PC_
        system("killall udhcpc");
        system("udhcpc -i eth2 &");
#endif 
        ManageWanModes(WAN_MODE_DOCSIS); 
        break;
 
       default: AUTO_WAN_LOG("This is not expected, setting WAN mode to Auto\n");
           SelectedWanMode(WAN_MODE_AUTO);
               ManageWanModes(WAN_MODE_DOCSIS); 
               break;   
    } 
}

void ManageWanModes(int mode)
{
    int try_mode = mode;
    int ret = 0;
    while(1)
    {
        ret = CheckWanConnection(try_mode);
        AUTO_WAN_LOG("%s - CheckWanConnection(%d) returned %d \n", __FUNCTION__, try_mode, ret);
            if(ret == 1)
            {
                // EWAN locked
                SetLastKnownWanMode(try_mode);
                SetCurrentWanMode(try_mode);
                if(try_mode == mode)
                {
                    // Can this ever happen?  Locked on EWAN and no reboot?
                    AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, reboot is not required, CheckWanConnection=%d\n",__FUNCTION__,WanModeStr(mode), ret);
#if defined(INTEL_PUMA7)
                    if(try_mode == WAN_MODE_ETH)
                    {
                        AUTO_WAN_LOG("%s - Shutting down DOCSIS\n", __FUNCTION__);
                        system("cmctl down");
                    }
#endif
                } //if(try_mode == mode)
                else
                {
                        AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, rebooting... \n",__FUNCTION__,WanModeStr(try_mode));
                        AutoWan_BkupAndReboot();
                }
            break;
            } // if(ret == 1)
            else if(ret == 2)
            {
                // DOCSIS Locked
                SetLastKnownWanMode(mode);
                SetCurrentWanMode(mode);
                AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, reboot is not required, CheckWanConnection=%d\n",__FUNCTION__,WanModeStr(mode), ret);
#if defined (_MACSEC_SUPPORT_)
                /* Stopping MACsec on Port since DOCSIS Succeeded */
                AUTO_WAN_LOG("%s - Stopping MACsec on %d\n",__FUNCTION__,ETHWAN_DEF_INTF_NUM);
                if ( RETURN_ERR == platform_hal_StopMACsec(ETHWAN_DEF_INTF_NUM)) {
                   AUTO_WAN_LOG("%s - MACsec stop error\n",__FUNCTION__);
                }
#endif
                RevertTriedConfig(mode);
            break;
            } // if(ret == 2)
            else
            {
                TryAltWan(&try_mode);
            }
    } //while(1)
}

int CheckWanConnection(int mode)
{
    int retry = 0;
    int WanLocked = 0;
    int ret = 0;
    while(retry < AUTOWAN_RETRY_CNT)
    {
        retry++;
        sleep(AUTOWAN_RETRY_INTERVAL);
        ret = CheckWanStatus(mode);
        if(ret == 1)
        {
            // No WAN connection
            AUTO_WAN_LOG("%s - Trying %s retry count %d\n",__FUNCTION__,WanModeStr(mode),retry);
        }
        else if(ret == 2)
        {
            // DOCSIS Locked
            AUTO_WAN_LOG("%s - WanMode %s is Locked %d\n",__FUNCTION__,WanModeStr(GetLastKnownWanMode()),retry);
            WanLocked = 2;
            break;
        }
        else
        {
            // EWAN Locked
            AUTO_WAN_LOG("%s - WanMode %s is Locked\n",__FUNCTION__,WanModeStr(mode));
            WanLocked = 1;
            break;
        }
    }
    return WanLocked;
}

#if 1
// For Gw_prov_utopia : Docsis running mode
extern int sysevent_fd_gs;
extern token_t sysevent_token_gs;
int CheckWanStatus(int mode)
{
   char buff[256] = {0};
   char command[256] = {0};
   FILE *fp;
   char *temp = NULL;
   char *found = NULL;
   char pRfSignalStatus = 0;
   int ret = 0;
   char wan_connection_ifname[ETHWAN_INTERFACE_NAME_MAX_LENGTH] = {0};

    if (mode == WAN_MODE_DOCSIS)
    {
        ret = docsis_IsEnergyDetected(&pRfSignalStatus);
        if( ret == RETURN_ERR )
        {
            AUTO_WAN_LOG("AUTOWAN Failed to get RfSignalStatus \n");
        }
        AUTO_WAN_LOG("AUTOWAN- %s Docsis present  - %d\n",__FUNCTION__,pRfSignalStatus); ///end
        if(pRfSignalStatus == 0)
        {
            AUTO_WAN_LOG("AUTOWAN DOCSIS wan not locked\n");
            return 1;
        }
        else
        {
           /* Validate DOCSIS Connection CMStatus */
           memset(command,0,sizeof(command));
           snprintf(command, sizeof(command), "dmcli eRT getv Device.X_CISCO_COM_CableModem.CMStatus |grep -i 'value'|awk '{print $5}' |cut -f3 -d:");
           memset(buff,0,sizeof(buff));

           /* Open the command for reading. */
           fp = popen(command, "r");
           if (fp == NULL)
           {
              printf("<%s>:<%d> Error popen\n", __FUNCTION__, __LINE__);
           }
           else
           {
              /* Read the output a line at a time - output it. */
              if (fgets(buff, 50, fp) != NULL)
              {
                 AUTO_WAN_LOG("AUTOWAN CM Status :%s\n", buff);
              }
              /* close */
              pclose(fp);
              found = strstr(buff,"OPERATIONAL");
              if(found)
              {
                 AUTO_WAN_LOG("AUTOWAN DOCSIS wan locked\n");
                 return 2;
              }
              else
              {
                 AUTO_WAN_LOG("AUTOWAN DOCSIS wan not locked\n");
                 return 1;
              }
           } //fp == NULL
           return 2;
        } //pRfSignalStatus == 0
    } //mode == WAN_MODE_DOCSIS

    if(mode == WAN_MODE_ETH)
    {
#if defined(AUTO_WAN_ALWAYS_RECONFIG_EROUTER)
        memset(buff,0,sizeof(buff));
        syscfg_get(NULL, "wan_physical_ifname", buff, sizeof(buff));

        AUTO_WAN_LOG("%s - syscfg returned wan_physical_ifname= %s\n",__FUNCTION__,buff);

        if(0 != strnlen(buff,sizeof(buff)))
        {
           snprintf(wan_connection_ifname, sizeof(wan_connection_ifname), "%s", buff);
        }
        else
        {
           snprintf(wan_connection_ifname, sizeof(wan_connection_ifname), "%s", WAN_PHY_NAME);
        }
#else
        if ( (0 != GWP_GetEthWanInterfaceName(wan_connection_ifname, sizeof(wan_connection_ifname)))
             || (0 == strnlen(wan_connection_ifname,sizeof(wan_connection_ifname)))
             || (0 == strncmp(wan_connection_ifname,"disable",sizeof(wan_connection_ifname)))
           )
        {
            /* Fallback case needs to set it default */
            snprintf(wan_connection_ifname , sizeof(wan_connection_ifname), "%s", ETHWAN_INF_NAME);
        }
#endif

        AUTO_WAN_LOG("%s - wan_connection_ifname= %s\n",__FUNCTION__,wan_connection_ifname);

        /* Validate IPv4 Connection on ETHWAN interface */
        memset(command,0,sizeof(command));
        snprintf(command, sizeof(command), "ifconfig %s |grep -i 'inet ' |awk '{print $2}' |cut -f2 -d:", wan_connection_ifname);
        memset(buff,0,sizeof(buff));

        /* Open the command for reading. */
        fp = popen(command, "r");
        if (fp == NULL)
        {
           printf("<%s>:<%d> Error popen\n", __FUNCTION__, __LINE__);

        }
        else
        {
            /* Read the output a line at a time - output it. */
            if (fgets(buff, 50, fp) != NULL)
            {
               printf("IP :%s", buff);
            }
            /* close */
            pclose(fp);
            if(buff[0] != 0)
            {
               return 0; // Shirish To-Do // Call validate IP function for GLOBAL IP check
            }
        } // fp == NULL

        /* Validate IPv6 Connection on ETHWAN interface */
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command), "ifconfig %s |grep -i 'inet6 ' |grep -i 'Global' |awk '{print $3}'", wan_connection_ifname);
        memset(buff,0,sizeof(buff));

        /* Open the command for reading. */
        fp = popen(command, "r");
        if (fp == NULL)
        {
           printf("<%s>:<%d> Error popen\n", __FUNCTION__, __LINE__);
        }
        else
        {
           /* Read the output a line at a time - output it. */
           if (fgets(buff, 50, fp) != NULL)
           {
              printf("IP :%s", buff);
           }
           /* close */
           pclose(fp);
           if(buff[0] != 0)
           {
              return 0;
           }
        } // fp == NULL)
    } // mode == WAN_MODE_ETH

return 1;
}
#endif

int TryAltWan(int *mode)
{
    char pRfSignalStatus = 0;
    char command[128] = {0};
    char out_value[20] = {0};
    char ethwan_ifname[ETHWAN_INTERFACE_NAME_MAX_LENGTH] = {0};
    char wanPhyName[20] = {0};
    int eRouterMode = ERT_MODE_IPV4;

#if defined(INTEL_PUMA7)
    char udhcpcEnable[20] = {0};
    char dibblerClientEnable[20] = {0};
#endif

    syscfg_get(NULL, "wan_physical_ifname", out_value, sizeof(out_value));

    AUTO_WAN_LOG("%s - syscfg returned wan_physical_ifname= %s\n",__FUNCTION__,out_value);

    if(0 != strnlen(out_value,sizeof(out_value)))
    {
       snprintf(wanPhyName, sizeof(wanPhyName), "%s", out_value);
    }
    else
    {
       snprintf(wanPhyName, sizeof(wanPhyName), "%s", WAN_PHY_NAME);
    }

    memset(out_value, 0, sizeof(out_value));
    if (!syscfg_get(NULL, "last_erouter_mode", out_value, sizeof(out_value)))
    {
       eRouterMode = atoi(out_value);
    }

    AUTO_WAN_LOG("%s - wanPhyName= %s erouter_mode=%d\n",__FUNCTION__,wanPhyName,eRouterMode);

#if defined(INTEL_PUMA7)
    memset(out_value, 0, sizeof(out_value));
    if (!syscfg_get(NULL, "UDHCPEnable", out_value, sizeof(out_value)))
    {
       snprintf(udhcpcEnable, sizeof(udhcpcEnable), "%s", out_value);
    }

    memset(out_value, 0, sizeof(out_value));
    if (!syscfg_get(NULL, "dibbler_client_enable", out_value, sizeof(out_value)))
    {
       snprintf(dibblerClientEnable, sizeof(dibblerClientEnable), "%s", out_value);
    }

    AUTO_WAN_LOG("%s - udhcpcEnable= %s dibblerClientEnable= %s\n",__FUNCTION__,udhcpcEnable,dibblerClientEnable);
#endif

    if(*mode == WAN_MODE_DOCSIS)
    { 
        if(CheckEthWanLinkStatus() != 0)
        {
           AUTO_WAN_LOG("%s - Trying Alternate WanMode - %s\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH));
           AUTO_WAN_LOG("%s - Alternate WanMode - %s not present\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH));
           return 1;
        }
        *mode = WAN_MODE_ETH;

        macaddr_t macAddr;
#if defined(INTEL_PUMA7)
        getNetworkDeviceMacAddress(&macAddr);
#else
        getWanMacAddress(&macAddr);
#endif
        int i = 0;
        printf("eRouter macAddr: ");
        for (i = 0 ; i < 6 ; i++)
        {
            printf("%2x ",macAddr.hw[i]);
        }
        printf("\n");

        char wan_mac[18];// = {0};
        snprintf(wan_mac, sizeof(wan_mac), "%02x:%02x:%02x:%02x:%02x:%02x", macAddr.hw[0], macAddr.hw[1], macAddr.hw[2],
                                                          macAddr.hw[3], macAddr.hw[4], macAddr.hw[5]);

        if ( (0 != GWP_GetEthWanInterfaceName(ethwan_ifname, sizeof(ethwan_ifname)))
             || (0 == strnlen(ethwan_ifname,sizeof(ethwan_ifname)))
             || (0 == strncmp(ethwan_ifname,"disable",sizeof(ethwan_ifname)))
           )
        {
            /* Fallback case needs to set it default */
            snprintf(ethwan_ifname , sizeof(ethwan_ifname), "%s", ETHWAN_INF_NAME);
        }

        AUTO_WAN_LOG("%s - before mode= %s ethwan_ifname= %s, wanPhyName= %s\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH),ethwan_ifname,wanPhyName);
#if defined (_BRIDGE_UTILS_BIN_)

        if ( syscfg_set( NULL, "eth_wan_iface_name", ethwan_ifname ) != 0 )
        {
        	AUTO_WAN_LOG( "syscfg_set failed for eth_wan_iface_name\n" );
        }
        else
        {
        	if ( syscfg_commit() != 0 )
                {
                    AUTO_WAN_LOG( "syscfg_commit failed for eth_wan_iface_name\n" );
                }

        }
#endif
        // detach EWAN interface from brlan0
        memset(command, 0, sizeof(command));
#if defined (_BRIDGE_UTILS_BIN_)

       	if (g_OvsEnable)
        {
        	snprintf(command,sizeof(command),"/usr/bin/bridgeUtils del-port brlan0 %s",ethwan_ifname);
        }	
       	else
        {
               	snprintf(command, sizeof(command), "ip link set dev %s nomaster", ethwan_ifname);
        }
#else
        snprintf(command, sizeof(command), "ip link set dev %s nomaster", ethwan_ifname);
#endif
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command, sizeof(command), "ip link set %s down", ethwan_ifname);
        system(command);

        // EWAN interface needs correct MAC before starting MACsec
        // This could probably be done once since MAC shouldn't change.
        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s address %s", ethwan_ifname, wan_mac);
        system(command);
        printf("************************value of command = %s***********************\n", command);
        AUTO_WAN_LOG("AUTOWAN %s cmd = %s\n",__FUNCTION__,command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ifconfig %s up", ethwan_ifname);
        system(command);

#if defined (_MACSEC_SUPPORT_)
        AUTO_WAN_LOG("%s - Starting MACsec on %d with %d second timeout\n",__FUNCTION__,ETHWAN_DEF_INTF_NUM,MACSEC_TIMEOUT_SEC);
        if ( RETURN_ERR == platform_hal_StartMACsec(ETHWAN_DEF_INTF_NUM, MACSEC_TIMEOUT_SEC)) {
            AUTO_WAN_LOG("%s - MACsec start returning error\n",__FUNCTION__);
        }
#endif

        CosaDmlEthWanSetEnable(TRUE);

        /* ETH WAN Interface must be retrieved a second time in case MACsec
           modified the interfaces. */
        memset(ethwan_ifname,0,sizeof(ethwan_ifname));
        if ( (0 != GWP_GetEthWanInterfaceName(ethwan_ifname, sizeof(ethwan_ifname)))
             || (0 == strnlen(ethwan_ifname,sizeof(ethwan_ifname)))
             || (0 == strncmp(ethwan_ifname,"disable",sizeof(ethwan_ifname)))
           )
        {
            /* Fallback case needs to set it default */
            snprintf(ethwan_ifname , sizeof(ethwan_ifname), "%s", ETHWAN_INF_NAME);
        }

        AUTO_WAN_LOG("%s - mode= %s ethwan_ifname= %s, wanPhyName= %s\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH),ethwan_ifname,wanPhyName);

#if defined (_BRIDGE_UTILS_BIN_)

        if ( syscfg_set( NULL, "eth_wan_iface_name", ethwan_ifname ) != 0 )
        {
        	AUTO_WAN_LOG( "syscfg_set failed for eth_wan_iface_name\n" );
        }
        else
        {
                if ( syscfg_commit() != 0 )
                {
                    AUTO_WAN_LOG( "syscfg_commit failed for eth_wan_iface_name\n" );
                }

        }
#endif
#if defined(_COSA_BCM_ARM_)
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"brctl addif %s %s",wanPhyName,DOCSIS_INF_NAME);
        system(command);
        //system("brctl addif erouter0 cm0");
#elif defined(AUTO_WAN_ALWAYS_RECONFIG_EROUTER)
        // move existing erouter interface erouter0@adp0 vlan 1000
        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s down; ip link set %s name dummy-rf", wanPhyName, wanPhyName);
        system(command);

        // setup erouter0 bridge for EWAN mode
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command), "ip link add %s type bridge", wanPhyName);
        system(command);

        // prevent EWAN interface from auto configuring an IPv6 address
        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "sysctl -w net.ipv6.conf.%s.autoconf=0", ethwan_ifname);
        system(command);
        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "sysctl -w net.ipv6.conf.%s.disable_ipv6=1", ethwan_ifname);
        system(command);

        // Attach EWAN interface
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s master %s", ethwan_ifname, wanPhyName);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ifconfig %s up", wanPhyName);
        system(command);
#endif

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ifconfig %s up", ethwan_ifname);
        system(command);

// need to start DHCPv6 client when eRouterMode == ERT_MODE_DUAL
        if (eRouterMode == ERT_MODE_IPV6)
        {
#if defined(INTEL_PUMA7)
            if(0 == strncmp(dibblerClientEnable, "yes", sizeof(dibblerClientEnable)))
            {
#endif
               system("killall dibbler-client");
               memset(command, 0, sizeof(command));
               snprintf(command,sizeof(command), "sh /etc/dibbler/dibbler-init.sh");
               system(command);
               memset(command, 0, sizeof(command));
               snprintf(command,sizeof(command), "/usr/sbin/dibbler-client start");
               system(command);
#if defined(INTEL_PUMA7)
            }
            else
            {
               system("killall ti_dhcpv6c");
               memset(command, 0, sizeof(command));
               snprintf(command,sizeof(command), "ti_dhcp6c -plugin /lib/libgw_dhcp6plg.so -i %s -p /var/run/erouter_dhcp6c.pid &", wanPhyName);
               system(command);
            }
#endif
        } // (eRouterMode == ERT_MODE_IPV6)
        else if(eRouterMode == ERT_MODE_IPV4 || eRouterMode == ERT_MODE_DUAL)
        {
#if defined(INTEL_PUMA7)
            if(0 == strncmp(udhcpcEnable, "yes", sizeof(udhcpcEnable)))
            {
               system("killall udhcpc");
               memset(command, 0, sizeof(command));
               snprintf(command,sizeof(command), "/sbin/udhcpc -i %s -p /tmp/udhcpc.erouter0.pid -s /etc/udhcpc.script &", wanPhyName);
               system(command);
            }
            else
            {
               system("killall ti_udhcpc");
               memset(command, 0, sizeof(command));
               snprintf(command,sizeof(command), "ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s -H DocsisGateway -p /var/run/eRT_ti_udhcpc.pid -B -b 4 &", wanPhyName);
               system(command);
            }
#else
            memset(command, 0, sizeof(command));
            snprintf(command,sizeof(command), "udhcpc -i %s &", ethwan_ifname);
            system(command);
            memset(command,0,sizeof(command));
            snprintf(command,sizeof(command),"sysctl -w net.ipv6.conf.%s.accept_ra=2",ethwan_ifname);
            system(command);
            //system("sysctl -w net.ipv6.conf.eth3.accept_ra=2");
            system("killall udhcpc");
            memset(command, 0, sizeof(command));
            snprintf(command,sizeof(command), "udhcpc -i %s &", ethwan_ifname);
            system(command);
#endif
        } // (eRouterMode == ERT_MODE_IPV4 || eRouterMode == ERT_MODE_DUAL)
    } // *mode == WAN_MODE_DOCSIS
    else
    {
        *mode = WAN_MODE_DOCSIS;

        if(eRouterMode == ERT_MODE_IPV4 || eRouterMode == ERT_MODE_DUAL)
        {
#if defined (INTEL_PUMA7)
           if(0 == strncmp(udhcpcEnable, "yes", sizeof(udhcpcEnable)))
           {
#endif
              system("killall udhcpc");
#if defined (INTEL_PUMA7)
           }
           else
           {
              system("killall ti_udhcpc");
           }
#endif
        } /* (eRouterMode == ERT_MODE_IPV4 || eRouterMode == ERT_MODE_DUAL)*/
        else if (eRouterMode == ERT_MODE_IPV6)
        {
#if defined (INTEL_PUMA7)
           if(0 == strncmp(dibblerClientEnable, "yes", sizeof(dibblerClientEnable)))
           {
#endif
              system("killall dibbler-client");
#if defined (INTEL_PUMA7)
           }
           else
           {
              system("killall ti_dhcpv6c");
           }
#endif
        } /*(eRouterMode == ERT_MODE_IPV6) */

        CosaDmlEthWanSetEnable(FALSE);

#if defined(AUTO_WAN_ALWAYS_RECONFIG_EROUTER)

        if ( (0 != GWP_GetEthWanInterfaceName(ethwan_ifname, sizeof(ethwan_ifname)))
             || (0 == strnlen(ethwan_ifname,sizeof(ethwan_ifname)))
             || (0 == strncmp(ethwan_ifname,"disable",sizeof(ethwan_ifname)))
           )
        {
            /* Fallback case needs to set it default */
            snprintf(ethwan_ifname ,sizeof(ethwan_ifname), "%s", ETHWAN_INF_NAME);
        }

        AUTO_WAN_LOG("%s - mode=%s ethwan_ifname=%s, wanPhyName=%s\n",__FUNCTION__,WanModeStr(WAN_MODE_DOCSIS),ethwan_ifname,wanPhyName);

        #if defined (_BRIDGE_UTILS_BIN_)

            if ( syscfg_set( NULL, "eth_wan_iface_name", ethwan_ifname ) != 0 )
            {
                AUTO_WAN_LOG( "syscfg_set failed for eth_wan_iface_name\n" );
            }
            else
            {
                if ( syscfg_commit() != 0 )
                {
                    AUTO_WAN_LOG( "syscfg_commit failed for eth_wan_iface_name\n" );
                }

            }
        #endif
        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s down", wanPhyName);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s down", ethwan_ifname);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set %s nomaster", ethwan_ifname);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "brctl delbr %s", wanPhyName);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ip link set dummy-rf name %s", wanPhyName);
        system(command);

        memset(command, 0, sizeof(command));
        snprintf(command,sizeof(command), "ifconfig %s up", wanPhyName);
        system(command);
#endif

    }
    AUTO_WAN_LOG("%s - Trying Alternate WanMode - %s\n",__FUNCTION__,WanModeStr(*mode));
    return 0;
}

void RevertTriedConfig(int mode)
{
    char command[64] = {0};
    char ethwan_ifname[ETHWAN_INTERFACE_NAME_MAX_LENGTH] = {0};

    AUTO_WAN_LOG("%s - mode %d\n",__FUNCTION__, mode);
    if(mode == WAN_MODE_DOCSIS)
    {
        if ( (0 != GWP_GetEthWanInterfaceName(ethwan_ifname, sizeof(ethwan_ifname)))
             || (0 == strnlen(ethwan_ifname,sizeof(ethwan_ifname)))
             || (0 == strncmp(ethwan_ifname,"disable",sizeof(ethwan_ifname)))
           )
        {
           /* Fallback case needs to set it default */
           snprintf(ethwan_ifname ,sizeof(ethwan_ifname), "%s", ETHWAN_INF_NAME);
        }

        AUTO_WAN_LOG("%s - ethwan_ifname= %s\n",__FUNCTION__,ethwan_ifname);

        #if defined (_BRIDGE_UTILS_BIN_)

            if ( syscfg_set( NULL, "eth_wan_iface_name", ethwan_ifname ) != 0 )
            {
                AUTO_WAN_LOG( "syscfg_set failed for eth_wan_iface_name\n" );
            }
            else
            {
                if ( syscfg_commit() != 0 )
                {
                    AUTO_WAN_LOG( "syscfg_commit failed for eth_wan_iface_name\n" );
                }

            }
        #endif

        snprintf(command,sizeof(command),"ifconfig %s down",ethwan_ifname);
        system(command);
        //system("ifconfig eth3 down");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"ip addr flush dev %s",ethwan_ifname);
        system(command);
        //system("ip addr flush dev eth3");
        // redundant because ip addr flush removes both v4 and v6
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"ip -6 addr flush dev %s",ethwan_ifname);
        system(command);
        //system("ip -6 addr flush dev eth3");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"sysctl -w net.ipv6.conf.%s.accept_ra=0",ethwan_ifname);
        system(command);
        //system("sysctl -w net.ipv6.conf.eth3.accept_ra=0");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"ifconfig %s up",ethwan_ifname);
        system(command);
        //system("ifconfig eth3 up");
        memset(command,0,sizeof(command));
#if defined (_BRIDGE_UTILS_BIN_)

        if (g_OvsEnable)
        {
            snprintf(command,sizeof(command),"/usr/bin/bridgeUtils add-port brlan0 %s",ethwan_ifname);
        }
        else
        {
            snprintf(command,sizeof(command),"brctl addif brlan0 %s",ethwan_ifname);
        }
#else
        snprintf(command,sizeof(command),"brctl addif brlan0 %s",ethwan_ifname);
#endif

        system(command);

        //system("brctl addif brlan0 eth3");
#if defined(_COSA_BCM_ARM_)
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"brctl addif erouter0 %s",DOCSIS_INF_NAME);
        system(command);
        //system("brctl addif erouter0 cm0");
#endif
    }
    else
    {
       // Don't think this case should never be executed
       AUTO_WAN_LOG("%s - shouldn't be here when mode is %d\n",__FUNCTION__,mode);

#if defined(_COSA_BCM_ARM_)
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"ip addr flush dev %s",DOCSIS_INF_NAME);
        system(command);
        //system("ip addr flush dev cm0");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"ip -6 addr flush dev %s",DOCSIS_INF_NAME);
        system(command);
        //system("ip -6 addr flush dev cm0");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"sysctl -w net.ipv6.conf.%s.accept_ra=0",DOCSIS_INF_NAME);
        system(command);
        //system("sysctl -w net.ipv6.conf.cm0.accept_ra=0");
        memset(command,0,sizeof(command));
        snprintf(command,sizeof(command),"brctl addif erouter0 %s",DOCSIS_INF_NAME);
        system(command);
        //system("brctl addif erouter0 cm0");
#endif
    }
}
int
CosaDmlEthWanSetEnable
    (
        BOOL                       bEnable
    )
{
#if ((defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_)) || defined(INTEL_PUMA7) || defined(_CBR2_PRODUCT_REQ_))
        BOOL bGetStatus = FALSE;
#if !defined(AUTO_WAN_ALWAYS_RECONFIG_EROUTER)
    char command[64] = {0};
    {
       if(bEnable == FALSE)
       {
        system("ifconfig erouter0 down");
        snprintf(command,sizeof(command),"ip link set erouter0 name %s",ETHWAN_INF_NAME);
        system(command);
        system("ip link set dummy-rf name erouter0");
        system("ifconfig eth0 up;ifconfig erouter0 up");
        
       } 
    }
#endif

    CcspHalExtSw_setEthWanPort ( ETHWAN_DEF_INTF_NUM );

    if ( RETURN_OK == CcspHalExtSw_setEthWanEnable( bEnable ) ) 
    {
        //pthread_t tid;        
        char buf[ 8 ];
        memset( buf, 0, sizeof( buf ) );
        snprintf( buf, sizeof( buf ), "%s", bEnable ? "true" : "false" );
        if(bEnable)
        {
            system("touch /nvram/ETHWAN_ENABLE");
        }
        else
        {
            system("rm /nvram/ETHWAN_ENABLE");
        }

        if ( syscfg_set( NULL, "eth_wan_enabled", buf ) != 0 )
        {
            AUTO_WAN_LOG( "syscfg_set failed for eth_wan_enabled\n" );
            return RETURN_ERR;
        }
        else
        {
            if ( syscfg_commit() != 0 )
            {
                AUTO_WAN_LOG( "syscfg_commit failed for eth_wan_enabled\n" );
                return RETURN_ERR;
            }
            
        }
    }
    return RETURN_OK;
#else
    return RETURN_ERR;
#endif /* (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_)) */
}

void AutoWan_BkupAndReboot()
{

/* Set the reboot reason */
                        char buf[8];
                        snprintf(buf,sizeof(buf),"%d",1);
                        if (syscfg_set(NULL, "X_RDKCENTRAL-COM_LastRebootReason", "WAN_Mode_Change") != 0)
                        {
                                AUTO_WAN_LOG("RDKB_REBOOT : RebootDevice syscfg_set failed GUI\n");
                        }
                        else
                        {
                                if (syscfg_commit() != 0)
                                {
                                        AUTO_WAN_LOG("RDKB_REBOOT : RebootDevice syscfg_commit failed for ETHWAN mode\n");
                                }
                        }


                        if (syscfg_set(NULL, "X_RDKCENTRAL-COM_LastRebootCounter", buf) != 0)
                        {
                                AUTO_WAN_LOG("syscfg_set failed\n");
                        }
                        else
                        {
                                if (syscfg_commit() != 0)
                                {
                                        AUTO_WAN_LOG("syscfg_commit failed\n");
                                }
                        }

    /* Need to do reboot the device here */
    system("dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Device");
}
#endif
