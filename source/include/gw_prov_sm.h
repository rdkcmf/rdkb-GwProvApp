#ifndef _GW_GWPROV_SM_H_
#define _GW_GWPROV_SM_H_

#ifdef FEATURE_SUPPORT_RDKLOG
void GWPROV_PRINT(const char *format, ...);
#else
#define GWPROV_PRINT printf
#endif

#endif
