/*

  BSD LICENSE 

  Copyright(c) 2006-2011 Intel Corporation. All rights reserved.

  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions 
  are met:

    * Redistributions of source code must retain the above copyright 
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in 
      the documentation and/or other materials provided with the 
      distribution.
    * Neither the name of Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef _SYS_PTYPES_H_
#define _SYS_PTYPES_H_

/***************************************************************************/
/*! \file sys_ptypes.h
    \brief The file defines common primitive types
****************************************************************************/

/**************************************************************************/
/*                                                                        */
/*  Primitives types definition                                           */
/*                                                                        */
/**************************************************************************
 *
 *  ALLOWS TYPES :
 *  --------------
 *  Char    - A character. Use for printable data with NULL terminator,
 *            e.g. strings( names, pathes, messages ...)
 *
 *  Uint8  -  8 bit unsigned variable;
 *            Use for network buffers and buffers which do not require signedness.
 *
 *  Int8    - 8 bit signed variable;
 *
 *  Uint16  - 16 bit unsigned variable;
 *
 *  Int16   - 16 bit signed variable;
 *
 *  Uint32  - 32 bit unsigned variable;
 *
 *  Int32   - 32 bit signed variable;
 *
 *  Uint64  - 64 bit unsigned variable;
 *
 *  Int64   - 64 bit signed variable;
 *
 *  Bool    - Boolean variables { True, Fasle }
 *
 **************************************************************************/

#include "_tistdtypes.h" /* Include the PSP primitive types */


#endif /* _SYS_PTYPES_H_ */

