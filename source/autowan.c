#ifdef AUTOWAN_ENABLE
#include <stdio.h>

#include<unistd.h> 
#include<stdint.h>
#include<errno.h> 
#include<sys/types.h> 
#include<sys/stat.h> 
#include<fcntl.h> 
#include "autowan.h"
#include "gw_prov_sm.h"
#include "cm_hal.h"
#include "ccsp_hal_ethsw.h"
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

int g_CurrentWanMode 		= 0;
int g_LastKnowWanMode 		= 0;
int g_SelectedWanMode 		= 0;
int g_AutoWanRetryCnt 		= 0;
int g_AutoWanRetryInterval 	= 0;

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
int TryAltWan(int *mode);
int CheckWanStatus();
int CheckWanConnection(int mode);
void RevertTriedConfig(int mode);
void AutoWan_BkupAndReboot();
int CheckEthWanLinkStatus();
int CheckEthWanLinkStatus()
{
    CCSP_HAL_ETHSW_PORT         port        = ETHWAN_INF_NUM;
    INT                         status;
    CCSP_HAL_ETHSW_LINK_RATE    LinkRate;
    CCSP_HAL_ETHSW_DUPLEX_MODE  DuplexMode;
    CCSP_HAL_ETHSW_LINK_STATUS  LinkStatus;

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
    g_CurrentWanMode 		= WAN_MODE_UNKNOWN;
    g_LastKnowWanMode 		= WAN_MODE_DOCSIS;
    g_SelectedWanMode 		= WAN_MODE_AUTO;
    g_AutoWanRetryCnt 		= AUTOWAN_RETRY_CNT;
    g_AutoWanRetryInterval 	= AUTOWAN_RETRY_INTERVAL;

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

int ManageWanModes(int mode)
{
    int try_mode = mode;
    int ret = 0;
    while(1)
    {
	ret = CheckWanConnection(try_mode);
    	if(ret == 1)
    	{
	    SetLastKnownWanMode(try_mode);
	    SetCurrentWanMode(try_mode);
	    if(try_mode == mode)
	    {
		AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, reboot is not required\n",__FUNCTION__,WanModeStr(mode));
            }
	    else
	    {
		AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, rebooting... \n",__FUNCTION__,WanModeStr(try_mode));
		AutoWan_BkupAndReboot();
	    }
            break;
    	}
    	else if(ret == 2)
    	{
	    SetLastKnownWanMode(mode);
	    SetCurrentWanMode(mode);
	    AUTO_WAN_LOG("%s - WanMode %s is Locked, Set Current operational mode, reboot is not required\n",__FUNCTION__,WanModeStr(mode));
            RevertTriedConfig(mode);
	   
            break;
    	}
    	else
    	{
	    TryAltWan(&try_mode);
	}
    }
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
	        AUTO_WAN_LOG("%s - Trying %s retry count %d\n",__FUNCTION__,WanModeStr(mode),retry);
	        
	    }
	    else if(ret == 2)
	    {
		AUTO_WAN_LOG("%s - WanMode %s is Locked %d\n",__FUNCTION__,WanModeStr(GetLastKnownWanMode()),retry);
		WanLocked = 2;
		break;
	    } 
	    else
	    {
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
   memset(buff,0,sizeof(buff));
   memset(command,0,sizeof(command));
	sysevent_get(sysevent_fd_gs, sysevent_token_gs, "current_wan_state", buff, sizeof(buff));

	if (!strcmp(buff, "up")) {
        ret = docsis_IsEnergyDetected(&pRfSignalStatus);
        if( ret == RETURN_ERR )
        {
                AUTO_WAN_LOG("AUTOWAN Failed to get RfSignalStatus \n");
        }
        AUTO_WAN_LOG("AUTOWAN- %s Dosis present  - %d\n",__FUNCTION__,pRfSignalStatus); ///end
        if(pRfSignalStatus == 0)
        {
		AUTO_WAN_LOG("AUTOWAN DOCSIS wan not locked\n");
                return 1;
        }
	else
	{
		/* Validate DOCSIS Connection CMStatus */
	       sprintf(command, "dmcli eRT getv Device.X_CISCO_COM_CableModem.CMStatus |grep -i 'value'|awk '{print $5}' |cut -f3 -d:");
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
               	 	AUTO_WAN_LOG("AUTOWAN CM Status :%s\n", buff);
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
               }
		   memset(command,0,sizeof(command));
		return 2;
          }
	}

	if(mode == WAN_MODE_ETH)
	{
		/* Validate IPv4 Connection on ETHWAN interface */
		sprintf(command, "ifconfig %s |grep -i 'inet ' |awk '{print $2}' |cut -f2 -d:", ETHWAN_INF_NAME);
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
               }
		/* Validate IPv6 Connection on ETHWAN interface */
		memset(command,0,sizeof(command));
		sprintf(command, "ifconfig %s |grep -i 'inet6 ' |grep -i 'Global' |awk '{print $3}'", ETHWAN_INF_NAME);
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
               }
	}


return 1;
}
#endif
int TryAltWan(int *mode)
{
int ret = 0;
char pRfSignalStatus = 0;
char command[64];
memset(command,0,sizeof(command));
    if(*mode == WAN_MODE_DOCSIS)
    { 
        if(CheckEthWanLinkStatus() != 0)
	{
	    AUTO_WAN_LOG("%s - Trying Alternet WanMode - %s\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH));
	    AUTO_WAN_LOG("%s - Alternet WanMode - %s not present\n",__FUNCTION__,WanModeStr(WAN_MODE_ETH));
	    return 1;

        }
        *mode = WAN_MODE_ETH;

	CosaDmlEthWanSetEnable(TRUE);
        memset(command,0,sizeof(command));
        sprintf(command,"brctl delif brlan0 %s",ETHWAN_INF_NAME);
        system(command);
	//system("brctl delif brlan0 eth3");
        memset(command,0,sizeof(command));
        sprintf(command,"brctl addif erouter0 %s",DOCSIS_INF_NAME);
        system(command);
	//system("brctl addif erouter0 cm0");
    {
    macaddr_t macAddr;
    int i =0;
        getWanMacAddress(&macAddr);
                printf("eRouter macAddr ");
                for (i=0;i<6;i++)
                {
                   printf("%2x ",macAddr.hw[i]);
                }
                printf(" \n");
    char wan_mac[18];// = {0};
    sprintf(wan_mac, "%02x:%02x:%02x:%02x:%02x:%02x",macAddr.hw[0],macAddr.hw[1],macAddr.hw[2],macAddr.hw[3],macAddr.hw[4],macAddr.hw[5]);
    memset(command,0,sizeof(command));
    sprintf(command,"ifconfig %s down",ETHWAN_INF_NAME);
    system(command);
    //system("ifconfig eth3 down");
    memset(command,0,sizeof(command));
    sprintf(command,"ifconfig %s hw ether %s",ETHWAN_INF_NAME,wan_mac);
    system(command);
    //sprintf(command, "ifconfig eth3 hw ether %s",wan_mac);
    printf("************************value of command = %s\***********************n", command);
    //system(command);
    AUTO_WAN_LOG("AUTOWAN %s cmd = %s\n",__FUNCTION__,command);
    memset(command,0,sizeof(command));
    sprintf(command,"ifconfig %s up",ETHWAN_INF_NAME);
    system(command);
    //system("ifconfig eth3 up");

    }
    memset(command,0,sizeof(command));
    sprintf(command,"udhcpc -i %s &",ETHWAN_INF_NAME);
    system(command);	
//system("rm -rf /tmp/wan_locked; udhcpc -i eth3 &");
    memset(command,0,sizeof(command));
    sprintf(command,"sysctl -w net.ipv6.conf.%s.accept_ra=2",ETHWAN_INF_NAME);
    system(command);
    //system("sysctl -w net.ipv6.conf.eth3.accept_ra=2");
    system("killall udhcpc");
    memset(command,0,sizeof(command));
    sprintf(command,"udhcpc -i %s &",ETHWAN_INF_NAME);
    system(command);  
    //system("udhcpc -i eth3 &");
    }
    else
    {
	/*ret = docsis_IsEnergyDetected(&pRfSignalStatus);
	if( ret == RETURN_ERR )
	{
		AUTO_WAN_LOG("AUTOWAN Failed to get RfSignalStatus \n");
	}
	AUTO_WAN_LOG("AUTOWAN- %s Dosis present  - %d\n",__FUNCTION__,pRfSignalStatus); ///end 
	 if(pRfSignalStatus)
	 {
	 	return ret;
	 }*/
        *mode = WAN_MODE_DOCSIS;
	system("killall udhcpc");
	CosaDmlEthWanSetEnable(FALSE);
    }
    AUTO_WAN_LOG("%s - Trying Alternet WanMode - %s\n",__FUNCTION__,WanModeStr(*mode));
}

void RevertTriedConfig(int mode)
{
char command[64];
memset(command,0,sizeof(command));
    if(mode == WAN_MODE_DOCSIS)
    {
        memset(command,0,sizeof(command));
        sprintf(command,"ifconfig %s down",ETHWAN_INF_NAME);
        system(command);
	//system("ifconfig eth3 down");
        memset(command,0,sizeof(command));
        sprintf(command,"ip addr flush dev %s",ETHWAN_INF_NAME);
        system(command);
	//system("ip addr flush dev eth3");
        memset(command,0,sizeof(command));
        sprintf(command,"ip -6 addr flush dev %s",ETHWAN_INF_NAME);
        system(command);
	//system("ip -6 addr flush dev eth3");
        memset(command,0,sizeof(command));
        sprintf(command,"sysctl -w net.ipv6.conf.%s.accept_ra=0",ETHWAN_INF_NAME);
        system(command);
	//system("sysctl -w net.ipv6.conf.eth3.accept_ra=0");
        memset(command,0,sizeof(command));
        sprintf(command,"ifconfig %s up",ETHWAN_INF_NAME);
        system(command);
	//system("ifconfig eth3 up");
        memset(command,0,sizeof(command));
        sprintf(command,"brctl addif brlan0 %s",ETHWAN_INF_NAME);
        system(command);
	//system("brctl addif brlan0 eth3");
        memset(command,0,sizeof(command));
        sprintf(command,"brctl addif erouter0 %s",DOCSIS_INF_NAME);
        system(command);
	//system("brctl addif erouter0 cm0");
 
    }
    else
    {
        memset(command,0,sizeof(command));
        sprintf(command,"ip addr flush dev %s",DOCSIS_INF_NAME);
        system(command);
	//system("ip addr flush dev cm0");
        memset(command,0,sizeof(command));
        sprintf(command,"ip -6 addr flush dev %s",DOCSIS_INF_NAME);
        system(command);
	//system("ip -6 addr flush dev cm0");
        memset(command,0,sizeof(command));
        sprintf(command,"sysctl -w net.ipv6.conf.%s.accept_ra=0",DOCSIS_INF_NAME);
        system(command);
	//system("sysctl -w net.ipv6.conf.cm0.accept_ra=0");
        memset(command,0,sizeof(command));
        sprintf(command,"brctl addif erouter0 %s",DOCSIS_INF_NAME);
        system(command);
	//system("brctl addif erouter0 cm0");
     
    }
}
int
CosaDmlEthWanSetEnable
    (
        BOOL                       bEnable
    )
{
#if (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_))
        BOOL bGetStatus = FALSE;
	{
	   if(bEnable == FALSE)
	   {
		system("ifconfig erouter0 down");
#ifdef _XB7_PRODUCT_REQ_        
		system("ip link set erouter0 name eth3");
#else
		system("ip link set erouter0 name eth0");
#endif
		system("ip link set dummy-rf name erouter0");
		system("ifconfig eth0 up;ifconfig erouter0 up");
		
	   } 
	}
#ifdef _XB7_PRODUCT_REQ_
			CcspHalExtSw_setEthWanPort ( 3 ); // need to set it to 3 eth3 interface for XB7
#else
			CcspHalExtSw_setEthWanPort ( 0 ); // need to set it to 0 eth0 interface after  TCXB6-4234 getting fixed
#endif
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
