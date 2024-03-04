//++----------------------------------------------------------------------
//
//
// Copyright (c) 2005-2022 Microsoft Corporation
//
// Module Name:        
//      dbglog.h
//
// Abstract:    
//      
//
// Author:
//      
//
// Revision History:     
//
//--------------------------------------------------------------------++// 
#ifndef __DEBUG_LOG_LIB_H__
#define __DEBUG_LOG_LIB_H__

//
// DEFINES
//

// error and success codes definition
#define MYDBG_SUCCESS                0
#define MYDBG_ERROR_ERROR           -1
#define MYDBG_ERROR_BADPARAMETER    -2
#define MYDBG_ERROR_OUTOFMEMORY     -3

#define DEBUG_LOG_ERROR       0x0001

//
// exported function declarations
//

void
PrintHexDump(
    IN DWORD  length,
    IN PBYTE  buffer
);

PVOID
DbglibLocalAlloc(
    IN ULONG ulBufferSize
);

void
DbglibLocalFree(
    IN PVOID pBuffer
);


#endif // __DEBUG_LOG_LIB_H__
