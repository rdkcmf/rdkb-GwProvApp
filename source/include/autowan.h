#ifndef _GW_GWPROV_AUTOWAN_H_
#define _GW_GWPROV_AUTOWAN_H_
#if defined (_COSA_BCM_ARM_)
#define DOCSIS_INF_NAME "cm0"
#if defined (_XB7_PRODUCT_REQ_)
#define ETHWAN_INF_NAME "eth3"
#elif defined (_CBR2_PRODUCT_REQ_)
#define ETHWAN_INF_NAME "eth5"
#else
#define ETHWAN_INF_NAME "eth0"
#endif
#elif defined (INTEL_PUMA7)
#define ETHWAN_INF_NAME "nsgmii0"
#endif
#define WAN_PHY_NAME "erouter0"
 #ifndef RETURN_OK
#define RETURN_OK   0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif
void AutoWAN_main();
#endif
