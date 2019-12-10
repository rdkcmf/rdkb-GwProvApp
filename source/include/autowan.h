#ifndef _GW_GWPROV_AUTOWAN_H_
#define _GW_GWPROV_AUTOWAN_H_
#ifdef _XB7_PRODUCT_REQ_
#define ETHWAN_INF_NAME "eth3"
#define ETHWAN_INF_NUM 4
#else
#define ETHWAN_INF_NAME "eth0"
#define ETHWAN_INF_NUM 1
#endif
#define DOCSIS_INF_NAME "cm0"
 #ifndef RETURN_OK
#define RETURN_OK   0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif
void AutoWAN_main();
#endif
