//++-------------------------------------------------------------------------
//
// Microsoft
//
// Copyright (c) 2004-2023 Microsoft Corporation
//
// Module Name:
//      webcli2023.cpp
//
// Abstract:
//      Schannel web client test application.
//      Originally derived from webclient.c, the MSDN SSL client sample
//
// Author:
//
//-----------------------------------------------------------------------++//
//
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <wincred.h>
#include <wincrypt.h>
#include <wintrust.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#define WEBSRV_WEBCLI_COMPLETED 2

#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#define TLS1_0_PROTOCOL_VERSION     TLS1_PROTOCOL_VERSION
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define TLS1_1_PROTOCOL_VERSION     0x0302
#define TLS1_2_PROTOCOL_VERSION     0x0303
#endif //(NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN8)
#define DTLS1_0_PROTOCOL_VERSION    0xfeff
#endif

#define TLS1_PROTOCOL_VERSION       0x0301

#include "dbglog.h"
#include "test_common.h"
#include "WebCli2023.h"

#define MAX_EAP_PRF 4
#define WINSOCK_VERSION_USED     0x0002
#define PKCS12_NAMED_NO_PERSIST_KEY 0x00020000  // PKCS12_NO_PERSIST_KEY and PKCS12_ALWAYS_CNG_KSP also need to be set

// maximum buffer size (16384 bytes)
#define MYMAX_BUFFER_LENGTH      0x4000  // setting a ceiling

#define COMBINEBYTES(hMsb, hLsb, Msb, Lsb)  ((DWORD)((DWORD) (((DWORD) (hMsb) << 24) | ((DWORD) (hLsb) << 16)))|((DWORD) (((DWORD) (Msb) << 8) | (DWORD) (Lsb))))

// For QCA/SCA SECPKG_ATTR_KEYING_MATERIAL/SECPKG_ATTR_KEYING_MATERIAL_INFO
const DWORD KEYING_MATERIAL_LENGTH = 512;  // Arbitrary requested length of keying material.

//
// GLOBALS
//

// User options.
LPSTR   g_pszServerName     = (LPSTR)"";
BOOL    g_fQryCtxtEapKeyBlock = FALSE;  // QueryContextAttributes NULL;

// set context attributes
DWORD   g_dwSetEapPRF = 0;

// QueryContextAttribute called and sizes populated
SecPkgContext_StreamSizes  pvSizesStream;

// Compat cli stuff
DWORD   g_dwNumServerSends = 0;

// Causes this client to send zero-length application data records to the server.
// This happens before, during and after app data payload and multiple ZLA records
// in a row.

// Early (false) start
BOOL    g_fEarlyStartReady = FALSE;
BOOL    g_fEarlyStartGetSent = FALSE;

DWORD* g_dwClientSendOffSet = 0;
DWORD* g_dwClientRecvOffSet = 0;
DWORD* g_dwServerSendOffSet = 0;

RTL_CRITICAL_SECTION* g_WebDllCritSec;
CHAR** ClientSendBuffer;
DWORD* ClientSendSize;

/*********************************************************************
 MAIN: Webclient works from here
*********************************************************************/
int main(int argc, char* argv[])
{
    DWORD dwStatus = MYDBG_ERROR_ERROR;

    WSADATA WsaData{};

    printf("Using Sockets...\n");

    if (argc <= 1)
    {
        Usage();
        goto cleanup;
    }

    g_pszServerName = argv[1];

    if (WSAStartup(WINSOCK_VERSION_USED, &WsaData) == SOCKET_ERROR)
    {
        printf("- Error %d returned by WSAStartup\n", GetLastError());
        goto cleanup;
    }

    //
    // call Webclient
    //
    dwStatus = WebClient();

cleanup:

    // Shutdown WinSock subsystem.
    WSACleanup();

    return dwStatus;
} // main()

/**********************************************************************
 Usage information
***********************************************************************/
void Usage(void)
{
    printf("\n");
    printf("USAGE: WebClientSample <DNS name of server>\n");
    printf("\n");
    
    exit(1);
} // Usage

/*********************************************************************
 Our precious WebClient
*********************************************************************/
unsigned long
WebClient()
{
    DWORD          dwStatus = MYDBG_ERROR_ERROR;
    INT            i = 0;
    SOCKET         Socket = INVALID_SOCKET;
    CredHandle     hClientCreds = { 0 };
    CtxtHandle     hContext = { 0 };
    SecBuffer      ExtraData = { 0 };

    BYTE* rgbBuffer = NULL;
    DWORD      cbData = 0;
    PBYTE      pbExtra = NULL;
    DWORD      cbExtra = 0;
    SecBuffer  ExtraBuffer = { 0 };
    QUIC_KEYS  quicApplicationKeys = { NULL, NULL, { 0 }, SSL_AES_GMC_NONCE_LENGTH, 0, NULL, NULL, { 0 }, SSL_AES_GMC_NONCE_LENGTH, 0 };
    BOOL       fReceivedCloseNotify = FALSE;
    // Track if the connection has been closed already.
    // for fUseSockets, this is when we receive a zero length message via ReceiveFromClient
    // otherwise, it is when recv returns 0 without error.
    BOOL       fConnectionReadClosed = FALSE;
    BOOL       fConnectionWriteClosed = FALSE;
    DWORD dwGracefulDrainStatus = 0;

    //
    // Dynamically allocate memory (to prevent stack buffer overruns)
    // and free it later.
    //
    rgbBuffer = (LPBYTE)DbglibLocalAlloc(IO_BUFFER_SIZE);
    if (NULL == rgbBuffer)
    {
        dwStatus = ERROR_NOT_ENOUGH_MEMORY;

        goto cleanup;
    }

    //=======================================================================
    // Initialize the Schannel Package
    //=======================================================================

    dwStatus = CreateDefaultClientCredentials(&hClientCreds);

    if (SEC_E_OK != dwStatus)
    {
        goto cleanup;
    }

    //=======================================================================
    // Connect to server.
    //=======================================================================
    if (dwStatus = ConnectToServer(g_pszServerName, 443, &Socket))
    {
        printf("- Error connecting to server!\n");
        goto cleanup;
    }

    printf("- Connected to %s on port: %d.\n", g_pszServerName, 443);

    //=======================================================================
    // Perform handshake
    //=======================================================================
    dwStatus = PerformClientHandshake(
        Socket,
        &hClientCreds,
        g_pszServerName,
        &hContext,
        &ExtraData,
        &quicApplicationKeys);
    if (MYDBG_SUCCESS != dwStatus)
    {
        if (ERROR_SUCCESS == dwStatus)
        {
            printf("- PerformClientHandshake was expected to fail here and it did.\n");
            dwStatus = MYDBG_SUCCESS;
        }
        goto cleanup;
    }

    printf("- HANDSHAKE WAS SUCCESSFUL.\n");

    //=======================================================================
    // Display connection info.
    //=======================================================================
    dwStatus = QueryContextWrapper(
        SECPKG_ATTR_CONNECTION_INFO,
        &hContext);

    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x querying connection info!\n", dwStatus);
        goto cleanup;
    }
    else
        printf("QueryContextWrraper\n");

    dwStatus = QueryContextWrapper(
        SECPKG_ATTR_CONNECTION_INFO_EX,
        &hContext);

    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x querying connection info!\n", dwStatus);
        goto cleanup;
    }
    else
        printf("QueryContextWrapperEx\n");

    //=======================================================================
    // Call QueryContextAttributes to get the buffer sizes
    //=======================================================================
    dwStatus = QueryContextBufferSizes(&hContext);
    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x querying buffer sizes!\n", dwStatus);
        goto cleanup;
    }

    //=======================================================================
    // call QueryContextAttributes wrapper to query other attributes
    //=======================================================================
    dwStatus = WebcliQueryContext(&hContext);
    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x querying context info!\n", dwStatus);
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }
    else
        printf("WebcliQueryContext called\n");

    //=======================================================================
    //
    // Fetch file from server.
    //
    //=======================================================================
    if (!g_fEarlyStartGetSent)
    {
        dwStatus = HttpsGetFile(
            Socket,
            &hClientCreds,
            &hContext,
            (LPSTR)"default.htm",
            &quicApplicationKeys,
            &ExtraData);
        if (dwStatus != SEC_E_OK)
        {
            printf("- Error fetching file from server!\n");

            goto cleanup;
        }
    }


    //=======================================================================
    //
    // multiple fetches, reconnections and renegotiations
    //
    //=======================================================================


    // First shutdown write side of connection so we don't deadlock on
    // receiving data.
    // shutdown Socket, returns 0 for success
    if (shutdown(Socket, SD_SEND))
    {
        printf("- Socket shutdown failed with %d!\n", WSAGetLastError());
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }

    fConnectionWriteClosed = TRUE;

    // Drain the connection gracefully. Process whatever data remains in transit.
    dwGracefulDrainStatus = DrainConnection(
        Socket,
        &hContext,
        &hClientCreds,
        rgbBuffer,
        IO_BUFFER_SIZE,
        &quicApplicationKeys,
        TRUE,
        &fReceivedCloseNotify);
    if (FAILED(dwGracefulDrainStatus))
    {
        printf("- DrainConnection failed with %d!\n", dwGracefulDrainStatus);
        dwStatus = dwGracefulDrainStatus;
        goto cleanup;
    }
    fConnectionReadClosed = TRUE;

cleanup:

    if (!fConnectionWriteClosed)
    {
        if (shutdown(Socket, SD_SEND))
        {
            printf("- Socket shutdown failed with %d!\n", WSAGetLastError());
        }
    }

    if (!fConnectionReadClosed)
    {
        // drain the receive half-open connection without processing the data.
        DWORD dwDrainStatus = DrainConnection(
            Socket,
            NULL,
            NULL,
            rgbBuffer,
            IO_BUFFER_SIZE,
            NULL,
            FALSE,
            NULL);
        if (FAILED(dwDrainStatus))
        {
            printf("- DrainConnection failed with %d!\n", dwDrainStatus);
        }
    }

    // Close socket.
    if (Socket != INVALID_SOCKET)
    {
        printf("- Closing Socket\n");

        // close the socket, returns 0 for success

        if (closesocket(Socket))
        {
            printf("- Socket close failed!\n");
        }
        Socket = INVALID_SOCKET;
    }

    // Free security context.
    if (hContext.dwLower || hContext.dwUpper)
    {
        DeleteSecurityContext(&hContext);
    }

    // Free SSPI credentials handle.
    if (hClientCreds.dwLower || hClientCreds.dwUpper)
    {
        FreeCredentialsHandle(&hClientCreds);
    }

    LocalFree(rgbBuffer);
    rgbBuffer = NULL;

    //DestroyQuicKeys(&quicApplicationKeys);

    if (ExtraData.pvBuffer)
    {
        LocalFree(ExtraData.pvBuffer);
    }

    if (ExtraBuffer.pvBuffer)
    {
        LocalFree(ExtraBuffer.pvBuffer);
    }

    return dwStatus;
}

unsigned long
CreateDefaultClientCredentials(
    IN OUT PCredHandle phClientCreds)
{
    unsigned long         dwStatus = MYDBG_ERROR_ERROR;
    TLS_PARAMETERS tlsParameters = { 0 };
    union
    {
        SCHANNEL_CRED v4;
        SCH_CREDENTIALS v5;
    } SchannelCred = { 0 };

    // cred version
    SchannelCred.v4.dwVersion = SCH_CREDENTIALS_VERSION;


    if (SchannelCred.v5.cTlsParameters > 0)
    {
        // The last parameter in the blacklist will hold the protocol version(s) blacklisted.
        SchannelCred.v5.pTlsParameters[SchannelCred.v5.cTlsParameters - 1].grbitDisabledProtocols = 0;
    }

    SchannelCred.v5.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;

    //
    // call ACH
    //

    printf("- Calling user ACH for default creds\n");
    dwStatus = AcquireCredentialsHandle(
        NULL,                   // Name of principal
        (LPSTR)UNISP_NAME,    // Name of package
        SECPKG_CRED_OUTBOUND,   // Flag indicating client side cred
        NULL,                   // Pointer to logon ID
        (PVOID)&SchannelCred,   // Package specific data
        NULL,                   // Pointer to GetKey() func
        NULL,                   // Value to pass to GetKey()
        phClientCreds,          // (out) Cred Handle
        NULL                    // (out) Lifetime (optional)
    );


    if (SEC_E_OK != dwStatus)
    {
        printf("- AcquireCredentialsHandle failed with error 0x%x!\n", dwStatus);
        //PrintSecurityError(dwStatus);
    }
    else
    {
        printf("- ACH returned success for default creds\n");
    }

    return dwStatus;
}

/*********************************************************************
 Open a socket to the specified server
*********************************************************************/
INT
ConnectToServer(
    IN     LPSTR    pszServerName,
    IN     INT      iPortNumber,
    OUT SOCKET* pSocket)
{
    SOCKET  Socket = INVALID_SOCKET;
    INT rc = 0;
    INT tempPort = 0;
    DWORD dwTimeout = 30 * 1000; //30 seconds
    BOOL fSuccess = FALSE;
    struct addrinfo* result = NULL,
        * temp = NULL;

    *pSocket = INVALID_SOCKET;

    tempPort = iPortNumber;
    rc = getaddrinfo(pszServerName, NULL, NULL, &result);

    if (rc != 0 || result == NULL)
    {
        printf(__FUNCTION__":**** Error %d returned by getaddrinfo\n", WSAGetLastError());

        return WSAGetLastError();
    }

    //Go through each result and attempt to connect.

    for (temp = result; temp != NULL; temp = temp->ai_next)
    {
        Socket = socket(temp->ai_family, SOCK_STREAM, 0);
        if (Socket == INVALID_SOCKET)
        {
            //Could be that V6 is not installed in this machine but server's name also returns a v6 record.
            continue;
        }
        SS_PORT(temp->ai_addr) = htons((USHORT)tempPort);

        //
        // connect-should succeed with one of the addresses returned by getaddrinfo
        //
        if (SOCKET_ERROR != connect(Socket, (PSOCKADDR)temp->ai_addr, temp->ai_addrlen))
        {
            fSuccess = TRUE;
            break;
        }
    }

    //Address Info is not required beyond this point. Since there are multiple return statements, freeing here ensures it is freed up before returning from this function.
    freeaddrinfo(result);

    if (fSuccess == FALSE)
    {
        printf(__FUNCTION__":**** Error %d:Could not connect with any of the addresses returned by getaddrinfo\n", WSAGetLastError());
        *pSocket = INVALID_SOCKET;
        return WSAGetLastError();
    }

    if (SOCKET_ERROR == setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&dwTimeout, sizeof(dwTimeout)))
    {
        printf(__FUNCTION__":**** Error %d:Could not set send timeout\n", WSAGetLastError());
    }

    if (SOCKET_ERROR == setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwTimeout, sizeof(dwTimeout)))
    {
        printf(__FUNCTION__":**** Error %d:Could not set send timeout\n", WSAGetLastError());
    }

    if (pSocket != NULL)
    {
        *pSocket = Socket;
    }

    return MYDBG_SUCCESS;
} // ConnectToServer()

//++----------------------------------------------------------------------
//  NAME:  PerformClientHandshake
//
//  DESC:  Kicks-off SSPI Handshake dance
//
//  ARGUMENTS:
//  - SOCKET Socket: socket to send data to server over
//  - PCredHandle phCreds: client cred handle
//  - LPSTR pszSrvName: dns name of server
//  - CtxtHandle phContext: input\output context handle
//  - SecBuffer* pExtraData: out extra secbuffer blob, caller is responsible for freeing this!
//
//  RETURNS:   nothing
//
//  NOTE:
//--------------------------------------------------------------------++//
unsigned long
PerformClientHandshake(
    IN     SOCKET          Socket,
    IN OUT PCredHandle     phCreds,
    IN     LPSTR           pszSrvName,
    IN OUT CtxtHandle* phContext,
    OUT SecBuffer* pExtraData,
    IN     PQUIC_KEYS      pQuicApplicationKeys)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    DWORD           cbData = 0;
    SecBufferDesc   InBuffer = { 0 };
    SecBuffer       InBuffers[6] = { 0 };
    DWORD           dwInBufferNum = 0;
    PSecBufferDesc  pInBuffer = NULL;
    SecBufferDesc   OutBufferDesc = { 0 };
    SecBuffer       OutBuffers[6] = { 0 };
    DWORD           dwOutBufferNum = 0;
    DWORD           dwSSPIFlags = 0;
    DWORD           dwSSPIOutFlags = 0;
    TimeStamp       tsExpiry = { 0 };
    PBYTE           pbToken = NULL;
    DWORD           cbToken = 0;
    PBYTE           pbAlert = NULL;
    DWORD           cbAlert = 0;
    PBYTE           pbSendToServer = NULL;
    DWORD           cbSendToServer = 0;
    DWORD           dwBuffer = 0;
    PSEND_GENERIC_TLS_EXTENSION pSendGenericTlsExtension = NULL;
    DWORD           dwGeContents = 0;
    PSecBuffer      pRetFlagsBuffer = NULL;
    SEC_FLAGS       reqExtendedFlags = { 0 };
    SEC_FLAGS       retExtendedFlags = { 0 };
    QUIC_KEYS       quicHandshakeKeys = { NULL, NULL, { 0 }, 0, 0, NULL, NULL, { 0 }, 0, 0 };

    //
    //  Initiate a client_hello message and generate a token.
    //

    if (reqExtendedFlags.Flags > 0)
    {
        InBuffers[dwInBufferNum].pvBuffer = &reqExtendedFlags;
        InBuffers[dwInBufferNum].cbBuffer = sizeof(reqExtendedFlags);
        InBuffers[dwInBufferNum].BufferType = SECBUFFER_FLAGS;
        dwInBufferNum++;
    }

    if (dwInBufferNum > 0)
    {
        InBuffer.cBuffers = dwInBufferNum;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;
        pInBuffer = &InBuffer;
    }

    // setup out buffers
    OutBuffers[dwOutBufferNum].pvBuffer = pbToken;
    OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_TOKEN;
    OutBuffers[dwOutBufferNum].cbBuffer = cbToken;
    dwOutBufferNum++;

    OutBuffers[dwOutBufferNum].pvBuffer = pbAlert;
    OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_ALERT;
    OutBuffers[dwOutBufferNum].cbBuffer = cbAlert;
    dwOutBufferNum++;

    if (reqExtendedFlags.Flags > 0)
    {
        OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_FLAGS;
        OutBuffers[dwOutBufferNum].cbBuffer = 0;
        OutBuffers[dwOutBufferNum].pvBuffer = nullptr;
        pRetFlagsBuffer = &OutBuffers[dwOutBufferNum];
        dwOutBufferNum++;
    }

    OutBufferDesc.cBuffers = dwOutBufferNum;
    OutBufferDesc.pBuffers = OutBuffers;
    OutBufferDesc.ulVersion = SECBUFFER_VERSION;

    dwSSPIFlags =
        ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;



    // First check whether we should send a hardcoded message,
    // and if yes, then use that message for OutBuffers[0]
    // and skip ISC.
    dwStatus = InitializeSecurityContextA(
        phCreds,                // Cred to base context
        NULL,                   // Existing context (OPT)
        pszSrvName,             // Target server name
        dwSSPIFlags,            // flags for ISC
        0,
        SECURITY_NATIVE_DREP,
        pInBuffer,
        0,
        phContext,
        &OutBufferDesc,
        &dwSSPIOutFlags,
        &tsExpiry);

    printf("- ISC returned 0x%lx\n", dwStatus);

    if (reqExtendedFlags.Flags > 0)
    {
        if (pRetFlagsBuffer == NULL ||
            pRetFlagsBuffer->pvBuffer == NULL ||
            pRetFlagsBuffer->cbBuffer < sizeof(SEC_FLAGS))
        {
            dwStatus = WEBCLI_ERROR_ERROR;
            goto cleanup;
        }

        retExtendedFlags = *(PSEC_FLAGS)pRetFlagsBuffer->pvBuffer;
    }

    //
    // Send response to server if there is one.
    // If there isn't an output token send an alert if available
    //
    if (OutBuffers[0].cbBuffer != 0 &&
        OutBuffers[0].pvBuffer != NULL)
    {
        pbSendToServer = (PBYTE)OutBuffers[0].pvBuffer;
        cbSendToServer = OutBuffers[0].cbBuffer;
    }
    else if (OutBuffers[1].cbBuffer != 0 &&
        OutBuffers[1].pvBuffer != NULL)
    {
        pbSendToServer = (PBYTE)OutBuffers[1].pvBuffer;
        cbSendToServer = OutBuffers[1].cbBuffer;
    }

    if (cbSendToServer != 0 && pbSendToServer != NULL)
    {
        cbData = send(
            Socket,
            (LPCSTR)pbSendToServer,
            cbSendToServer,
            0);
        g_dwNumServerSends++;

        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            printf("- Error code %d sending data to server!\n", WSAGetLastError());

            dwStatus = MYDBG_ERROR_ERROR;
            goto error;
        }

        printf("- %d bytes of handshake data sent\n", cbData);

        PrintHexDump(cbData, pbSendToServer);
    }

    // first call, ISC must return SEC_I_CONTINUE_NEEDED

    if (dwStatus != SEC_I_CONTINUE_NEEDED &&
        dwStatus != SEC_E_BUFFER_TOO_SMALL)
    {
        printf("- ISC FAILED (didn't return SEC_I_CONTINUE_NEEDED)!\n");
        goto error;
    }

    if (pExtraData != NULL)
    {
        pExtraData->pvBuffer = NULL;
        pExtraData->cbBuffer = 0;
    }

    dwStatus = ClientHandshakeLoop(
        Socket,
        phCreds,
        phContext,
        TRUE,
        pExtraData,
        &quicHandshakeKeys,
        pQuicApplicationKeys);

    // reset early start readiness
    g_fEarlyStartReady = FALSE;

    goto cleanup;

error:
    if (phContext)
    {
        DeleteSecurityContext(phContext);
        phContext = NULL;
    }

cleanup:

    if (pSendGenericTlsExtension != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pSendGenericTlsExtension);
        pSendGenericTlsExtension = NULL;
    }

    if (pRetFlagsBuffer != NULL)
    {
        FreeOutputBuffer(pRetFlagsBuffer);
        pRetFlagsBuffer->pvBuffer = NULL;
    }

    //
    // Free the output buffers
    //
    for (dwBuffer = 0; dwBuffer < OutBufferDesc.cBuffers; dwBuffer++)
    {
        FreeOutputBuffer(&OutBuffers[dwBuffer]);
    }

    return dwStatus;
}

/********************************************************************
 Conducts the SSPI handshake dance

 pExtraData->pvBuffer is read and is always changed after ClientHandshakeLoop finishes.

 If pExtraData->pvBuffer after ClientHandshakeLoop finishes is not NULL then
 pExtraData->pvBuffer contains more extra data, different than what was passed in
 and which needs to be freed by the caller.

 If pExtraData->pvBuffer after ClientHandshakeLoop finishes is NULL then
 then there is no more extra data.

 If caller passes in pExtraData, it will be read and passed to lsass
 via InitializeSecurityContext, and the pExtraData->pvBuffer will be overwritten
 with a pointer to new extra data (if there is any else NULL), so
 the caller needs to make sure the pExtraData->pvBuffer passed in can is reachable
 by the caller and can be freed by the caller after ClientHandshakeLoop finishes
 if the pExtraData->pvBuffer passed in was heap allocated possibly by keeping a copy
 in the calling function or otherwise.

********************************************************************/
unsigned long
ClientHandshakeLoop(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN OUT CtxtHandle* phContext,
    IN     BOOL            fDoInitialRead,
    IN OUT SecBuffer* pExtraData,
    IN     PQUIC_KEYS      pQuicHandshakeKeys,
    IN     PQUIC_KEYS      pQuicApplicationKeys)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    DWORD           dwCredStatus = WEBCLI_ERROR_ERROR;
    CredHandle      hLocalCreds = { 0 };
    SecBufferDesc   InBuffer = { 0 };
    SecBuffer       InBuffers[6] = { 0 };
    SecBufferDesc   OutBuffer = { 0 };
    SecBuffer       OutBuffers[10] = { 0 };
    DWORD           dwSSPIFlags = 0;
    DWORD           dwSSPIOutFlags = 0;
    TimeStamp       tsExpiry = { 0 };
    DWORD           cbData = 0;
    PUCHAR          IoBuffer = NULL;
    DWORD           cbIoBuffer = 0;
    BOOL            fDoRead = FALSE;
    PCCERT_CONTEXT  pRemoteCert = NULL;
    PSEND_GENERIC_TLS_EXTENSION pSendGenericTlsExtension = NULL;
    DWORD           cbSendGenericTlsExtension = 0;
    PSUBSCRIBE_GENERIC_TLS_EXTENSION pSubscribeGenericTlsExtension = NULL;
    DWORD           cbSubscribeGenericTlsExtension = 0;
    DWORD           dwGeContents = 0;
    BOOLEAN         fReceivedGenericExtension = FALSE;
    DWORD           dwInBufferNum = 0;
    DWORD           dwOutBufferNum = 0;
    SEC_FLAGS       reqExtendedFlags = { 0 };
    PSEC_FLAGS      pRetExtendedFlags = NULL;
    PSecBuffer      pRetFlagsBuffer = NULL;
    PSecBuffer      pSubscribeBuffer = NULL;
    DWORD           cbTrafficSecretsSize = 0;
    PSecBuffer      pTrafficSecrets[4] = { 0 };
    BCRYPT_ALG_HANDLE hSymmetricAlg = NULL;
    PSEC_TRAFFIC_SECRETS pHandshakeSecret = NULL;
    BOOLEAN         fReceivedData = FALSE;
    BOOLEAN         fIsPosthandshakeMessage = pQuicHandshakeKeys == NULL &&
        pQuicApplicationKeys == NULL;

    // SECPKG_ATTR_CERT_CHECK_RESULT
    // During SSPI loop, each time we receive a message from the server,
    // we will query this context attribute. Once the server sends the server
    // certificate, this attribute will become available and we will set
    // fQryCertValidationResultReceivedServerCert. If the certificate is also valid,
    // we will also set fQryCertValidationResultIsServerCertValid. This means at the end, 
    // If !fQryCertValidationResultReceivedServerCert we never received a server cert
    // If !fQryCertValidationResultIsServerCertValid we received an invalid server cert
    // Else we received a valid cert.
    BOOL fQryCertValidationResultReceivedServerCert = FALSE;
    BOOL fQryCertValidationResultIsServerCertValid = FALSE;

    // SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT
    // Works the same as SECPKG_ATTR_CERT_CHECK_RESULT in that we query until we receive
    // the cert buffer.
    BOOL fQrySerializedRemoteCertComplete = FALSE;

    // Initialize hLocalCreds for SecIsValidHandle check.
    SecInvalidateHandle(&hLocalCreds);

    //
    // set required flags
    //
    dwSSPIFlags =
        ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;

    //
    // Allocate data buffer.
    //

    cbIoBuffer = 0;
    IoBuffer = (PUCHAR)DbglibLocalAlloc(IO_BUFFER_SIZE);
    if (IoBuffer == NULL)
    {
        printf("- Out of memory!\n");
        dwStatus = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    //
    // Copy input data if it's provided.
    //

    if (pExtraData->pvBuffer && pExtraData->cbBuffer)
    {
        memcpy(IoBuffer, pExtraData->pvBuffer, pExtraData->cbBuffer);
        cbIoBuffer = pExtraData->cbBuffer;
    }

    //
    // Loop until the handshake is finished or an error occurs.
    //

    fDoRead = fDoInitialRead;
    dwStatus = SEC_I_CONTINUE_NEEDED;

    while (dwStatus == SEC_I_CONTINUE_NEEDED ||
        dwStatus == SEC_E_INCOMPLETE_MESSAGE ||
        dwStatus == SEC_I_INCOMPLETE_CREDENTIALS ||
        dwStatus == SEC_E_BUFFER_TOO_SMALL ||
        dwStatus == SEC_E_EXT_BUFFER_TOO_SMALL ||
        dwStatus == SEC_I_GENERIC_EXTENSION_RECEIVED ||
        dwStatus == SEC_E_INSUFFICIENT_BUFFERS)
    {

        //
        // Read data from server.
        //

        if (0 == cbIoBuffer ||
            dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            // get (more) data
            if (fDoRead)
            {
                cbData = recv(
                    Socket,
                    (LPSTR)(IoBuffer + cbIoBuffer),
                    min(IO_BUFFER_SIZE, IO_BUFFER_SIZE - cbIoBuffer),
                    0);

                if (cbData == SOCKET_ERROR)
                {
                    printf("- Error %d reading data from server!\n", WSAGetLastError());
                    dwStatus = MYDBG_ERROR_ERROR;
                    goto cleanup;
                }
                else if (cbData == 0)
                {
                    printf("- Server unexpectedly disconnected\n");
                    dwStatus = MYDBG_ERROR_ERROR;
                    goto cleanup;
                }

                printf("- %d bytes of handshake data received\n", cbData);
                printf("- Received data buffer:\n");
                PrintHexDump(cbData, IoBuffer + cbIoBuffer);

                cbIoBuffer += cbData;
                fReceivedData = TRUE;
            }
            else
            {
                fDoRead = TRUE;
            }
        }

        //
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        //
        dwInBufferNum = 0;

        InBuffers[dwInBufferNum].pvBuffer = IoBuffer;
        InBuffers[dwInBufferNum].cbBuffer = cbIoBuffer;
        InBuffers[dwInBufferNum].BufferType = SECBUFFER_TOKEN;
        dwInBufferNum++;

        InBuffers[dwInBufferNum].pvBuffer = NULL;
        InBuffers[dwInBufferNum].cbBuffer = 0;
        InBuffers[dwInBufferNum].BufferType = SECBUFFER_EMPTY;
        dwInBufferNum++;

        if (reqExtendedFlags.Flags > 0)
        {
            InBuffers[dwInBufferNum].pvBuffer = &reqExtendedFlags;
            InBuffers[dwInBufferNum].cbBuffer = sizeof(reqExtendedFlags);
            InBuffers[dwInBufferNum].BufferType = SECBUFFER_FLAGS;
            dwInBufferNum++;
        }

        InBuffer.cBuffers = dwInBufferNum;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        dwOutBufferNum = 0;

        // Token buffer
        dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], false, false, 0);
        if (dwStatus != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_TOKEN;
        dwOutBufferNum++;

        // Alert buffer
        dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], false, false, 0);
        if (dwStatus != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_ALERT;
        dwOutBufferNum++;

        // Context returned flags buffer
        if (reqExtendedFlags.Flags > 0)
        {
            dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], false, false, sizeof(SEC_FLAGS));
            if (dwStatus != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_FLAGS;
            pRetFlagsBuffer = &OutBuffers[dwOutBufferNum];
            dwOutBufferNum++;
        }

        OutBuffer.cBuffers = dwOutBufferNum;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //
        dwStatus = InitializeSecurityContextA(
            phCreds,
            phContext,
            NULL,
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            &InBuffer,
            0,
            NULL,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

        printf("- ISC returned 0x%lx\n", dwStatus);

        if (dwStatus == SEC_E_BUFFER_TOO_SMALL ||
            dwStatus == SEC_E_INSUFFICIENT_BUFFERS)
        {
            //loop around to reallocate
            continue;
        }

        if (dwStatus == SEC_E_EXT_BUFFER_TOO_SMALL)
        {
            continue;
        }

        if (dwStatus == SEC_I_GENERIC_EXTENSION_RECEIVED)
        {
            fReceivedGenericExtension = ReceivedExpectedGenericExtension(pSubscribeBuffer);

            FreeOutputBuffer(pSubscribeBuffer);
            pSubscribeBuffer->cbBuffer = 0;
            continue;
        }

        if (reqExtendedFlags.Flags > 0)
        {
            if (pRetFlagsBuffer == NULL || pRetFlagsBuffer->pvBuffer == NULL || pRetFlagsBuffer->cbBuffer < sizeof(SEC_FLAGS))
            {
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }

            pRetExtendedFlags = (PSEC_FLAGS)pRetFlagsBuffer->pvBuffer;

            FreeOutputBuffer(pRetFlagsBuffer);
            pRetFlagsBuffer->cbBuffer = 0;
        }

        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //
        if (dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            int i = 0;

            printf("- ISC returned SEC_E_INCOMPLETE_MESSAGE.. looping\n");

            for (; i < 2; i++)
            {
                if (SECBUFFER_MISSING == InBuffers[i].BufferType)
                {
                    printf("- Type- %d = SECBUFFER_MISSING.\n", InBuffers[i].BufferType);
                    printf("- %d bytes of decrypted missing data.\n", InBuffers[i].cbBuffer);
                    //
                    // Check if the buffer missing buffer actually has a
                    // value in the cbBuffer field.
                    //
                    if (InBuffers[i].cbBuffer == 0)
                    {
                        printf(" - ISC returned SECBUFFER_MISSING but cbValue field of the buffer was 0\n");
                        dwStatus = MYDBG_ERROR_ERROR;
                        goto cleanup;
                    }

                    break;
                }
            }

            continue;
        }

        //
        // Check if an Alert was generated
        //
        if (OutBuffers[1].cbBuffer != 0 && OutBuffers[1].pvBuffer != NULL)
        {
            // We have an alert

            printf("An ALERT was generated to send over to the server\n");
            PrintHexDump(OutBuffers[1].cbBuffer, (PBYTE)OutBuffers[1].pvBuffer);

            if (FAILED(dwStatus) && OutBuffers[0].cbBuffer == 0)
            {
                //
                // Handle as an extended error
                //
                dwSSPIOutFlags |= ISC_RET_EXTENDED_ERROR;
                FreeOutputBuffer((PSecBuffer)OutBuffers[0].pvBuffer);

                OutBuffers[0].cbBuffer = OutBuffers[1].cbBuffer;
                OutBuffers[0].pvBuffer = OutBuffers[1].pvBuffer;
            }
            else
            {
                FreeOutputBuffer(&OutBuffers[1]);

                printf("The ALERT was not sent to the server. The Output Token generated will be sent instead\n");
            }

            OutBuffers[1].pvBuffer = NULL;
        }

        //
        // If InitializeSecurityContext was successful (or if the error was
        // one of the special extended ones), send the contents of the output
        // buffer to the server.
        //
        if (dwStatus == SEC_E_OK ||
            dwStatus == SEC_I_CONTINUE_NEEDED ||
            dwStatus == SEC_I_CONTINUE_NEEDED_MESSAGE_OK ||
            (FAILED(dwStatus) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
        {
            // check if output buffers do have something
            if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                // send
                cbData = send(
                    Socket,
                    (LPCSTR)OutBuffers[0].pvBuffer,
                    OutBuffers[0].cbBuffer,
                    0);
                g_dwNumServerSends++;

                if (cbData == SOCKET_ERROR || cbData == 0)
                {
                    printf("- Error %d sending data to server!\n", WSAGetLastError());
                    dwStatus = MYDBG_ERROR_ERROR;
                    goto cleanup;
                }

                printf("- %d bytes of handshake data sent.\n", cbData);
                printf("- Sent data buffer:\n");
                PrintHexDump(cbData, (PBYTE)OutBuffers[0].pvBuffer);

                // Free output buffer
                FreeOutputBuffer(&OutBuffers[0]);
                FreeOutputBuffer(&OutBuffers[1]);
            }

            // check if early start request was acknowledged
            if (dwStatus == SEC_I_CONTINUE_NEEDED_MESSAGE_OK)
            {
                printf("- EarlyStart not requested. SEC_I_CONTINUE_NEEDED_MESSAGE_OK seen.\n");

                g_fEarlyStartReady = TRUE;
                printf("- EarlyStart request approved. SEC_I_CONTINUE_NEEDED_MESSAGE_OK.\n");

                // Check if QueryContextAttributes to get the buffer sizes succeeds before handshake completion
                dwStatus = QueryContextBufferSizes(phContext);
                if (dwStatus != SEC_E_OK)
                {
                    printf("- EarlyStart Error 0x%x querying buffer sizes!\n", dwStatus);

                    goto cleanup;

                }
                else
                {
                    printf("- EarlyStart querying buffer sizes succeeded! 0x%x", dwStatus);
                }

                // Send app data before handshake completion
                if ((dwStatus = HttpsGetFile(Socket,
                    phCreds,
                    phContext,
                    (LPSTR)"default.htm",
                    pQuicApplicationKeys,
                    NULL)) != SEC_E_OK)
                {
                    printf("- EarlyStart Error fetching file from server!\n");

                    goto cleanup;

                }
                else
                {
                    printf("- EarlyStart fetching file from server succeeded!\n");
                }

                //reset to continue handshake loop
                dwStatus = SEC_I_CONTINUE_NEEDED;
            }
        }

        //
        // If InitializeSecurityContext returned SEC_E_OK, then the
        // handshake completed successfully.
        //
        if (dwStatus == SEC_E_OK)
        {
            //
            // If the "extra" buffer contains data, this is encrypted
            // application protocol layer stuff. It needs to be saved.
            // The application layer will later decrypt it with
            // DecryptMessage.
            //

            if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);
                if (pExtraData->pvBuffer == NULL)
                {
                    printf("- Out of memory!\n");
                    goto cleanup;
                }

                //
                // copy the data from InBuffers[1].pvBuffer
                // (weird calculation to get InBuffers[1]pvBuffer address
                //  inside IoBuffer) to pExtraData->pvbuffer
                //
                MoveMemory(pExtraData->pvBuffer,
                    IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                    InBuffers[1].cbBuffer);

                pExtraData->cbBuffer = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                printf("- %d bytes of app data bundled as SECBUFFER_EXTRA with handshake data.\n", pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer = NULL;
                pExtraData->cbBuffer = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            //
            // Bail out to quit
            //
            break;
        }

        //
        // Check for fatal error.
        //

        if (FAILED(dwStatus))
        {
            printf("- ISC failed with error 0x%x!!\n", dwStatus);
            break;
        }

        // Query SECPKG_ATTR_ISSUER_LIST_EX if requested
        // This needs to be done after we receive the first flight of messages
        // from the server as this is when we receive the certificate request and
        // it is the only time the issuer list will be available to query.


        //
        // If InitializeSecurityContext returned
        // SEC_I_INCOMPLETE_CREDENTIALS, then the server just
        // requested client authentication.
        //

        if (dwStatus == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            printf("- ISC ret SEC_I_INCOMPLETE_CREDENTIALS, CliAuth required.\n");



            //=============================================================
            // Create NEW client creds based on options
            //=============================================================

            // marshall client credentials
            // We'll come here if server requests client auth but we didn't 
            // supply it earlier.
            dwCredStatus = CreateClientCredentials(
                nullptr,
                nullptr,
                &hLocalCreds);
            if (MYDBG_SUCCESS != dwCredStatus)
            {
                printf("- Error creating credentials!\n");
                break;
            }
            phCreds = &hLocalCreds;

            // Go around again.
            fDoRead = TRUE;  //FALSE
            continue;
        }

        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //
        if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            // When not using the Schannel record layer this
            // scenario has been handled in CustomRecordLayer.
            printf("- Extra data from ISC call. Moving and looping.\n");
            MoveMemory(IoBuffer,
                IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                InBuffers[1].cbBuffer);
            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    } // while(...)

cleanup:

    if (pSendGenericTlsExtension != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pSendGenericTlsExtension);
        pSendGenericTlsExtension = NULL;
    }

    if (pSubscribeGenericTlsExtension != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pSubscribeGenericTlsExtension);
        pSubscribeGenericTlsExtension = NULL;
    }

    // Free token buffer
    FreeOutputBuffer(&OutBuffers[0]);

    // Free alert buffer
    FreeOutputBuffer(&OutBuffers[1]);

    FreeOutputBuffer(pRetFlagsBuffer);

    for (int i = 0; i < COUNT_OF_TRAFFIC_SECRETS; i++)
    {
        FreeOutputBuffer(pTrafficSecrets[i]);
    }

    if (IoBuffer)
    {
        LocalFree(IoBuffer);
        IoBuffer = NULL;
    }

    if (SecIsValidHandle(&hLocalCreds))
    {
        FreeCredentialsHandle(&hLocalCreds);
    }

    if (hSymmetricAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hSymmetricAlg, 0);
    }

    return dwStatus;
} // ClientHandshakeLoop()

BOOLEAN
ReceivedExpectedGenericExtension(
    _In_ PSecBuffer pReceivedExtensions)
{
    int contentsLength = 0;

    if (pReceivedExtensions == NULL ||
        pReceivedExtensions->cbBuffer < sizeof(DWORD))
    {
        return FALSE;
    }

    BOOLEAN fReceivedExpectedGenericExtension = FALSE;
    PBYTE pbGenericTlsExtensions = (PBYTE)pReceivedExtensions->pvBuffer;
    DWORD cbGenericTlsExtensions = pReceivedExtensions->cbBuffer;
    DWORD extensionType = COMBINEBYTES(0, 0, pbGenericTlsExtensions[0], pbGenericTlsExtensions[1]);
    DWORD extensionSize = COMBINEBYTES(0, 0, pbGenericTlsExtensions[2], pbGenericTlsExtensions[3]);
    pbGenericTlsExtensions += sizeof(DWORD);
    cbGenericTlsExtensions -= sizeof(DWORD);

    if (cbGenericTlsExtensions != extensionSize)
    {
        goto Cleanup;
    }

    contentsLength = 0;

    if (ULONG_MAX != extensionType ||
        contentsLength != extensionSize)
    {
        goto Cleanup;
    }


    fReceivedExpectedGenericExtension = TRUE;



Cleanup:

    return fReceivedExpectedGenericExtension;
}

DWORD
QueryContextBufferSizes(IN PCtxtHandle phContext)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;

    //
    // Read stream or connection encryption properties.
    //



    dwStatus = QueryContextAttributes(
        phContext,
        SECPKG_ATTR_STREAM_SIZES,
        &pvSizesStream);

    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x reading SECPKG_ATTR_STREAM_SIZES.\n", dwStatus);
        return dwStatus;
    }

    printf("-");
    printf("  Header: %d, Trailer: %d, MaxMessage: %d\n",
        pvSizesStream.cbHeader, pvSizesStream.cbTrailer,
        pvSizesStream.cbMaximumMessage);

    return dwStatus;
}

/*********************************************************************
 Calls HTTPSendRequest and receives Response and data
*********************************************************************/
unsigned long
HttpsGetFile(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN     CtxtHandle* phContext,
    IN     LPSTR           pszFileName,
    IN     PQUIC_KEYS      pQuicApplicationKeys,
    IN     SecBuffer* pExtraData)
{
    SECURITY_STATUS dwStatus = WEBCLI_ERROR_ERROR;
    SecBufferDesc   Message = { 0 };
    SecBuffer       Buffers[4] = { 0 };
    SecBuffer       ExtraBuffer = { 0 };
    HANDLE          hFile = INVALID_HANDLE_VALUE;

    // Will hold data received.
    PBYTE           pbIoBuffer = NULL;
    // Will hold amt of data received.
    DWORD           cbIoBuffer = 0;
    DWORD           cbIoBufferLength = 0;
    // More extra data we get from SslReadPacket. pExtraData is extra data we may have already got
    // and if we already did get extra data, we'll put it in pbIoBuffer first.
    PBYTE           pbExtra = NULL;
    DWORD           cbExtra = 0;
    PBYTE           pbHeader = NULL;
    DWORD           cbHeader = 0;
    DWORD           fHeader = TRUE;
    DWORD           dwContentLength = 0;
    DWORD           cbContentRead = 0;
    DWORD           cbContentWritten = 0;
    BOOL            fSuccess = FALSE;
    DWORD           cbData = 0;
    INT             i = 0;
    DWORD           cbProtocolOverhead = 0;
    BOOLEAN         fReceivedExpectedServerSpeaksFirstMessage = FALSE;

    // If earlystart don't wait for server reply
    if (g_fEarlyStartReady && !g_fEarlyStartGetSent)
    {
        //
        // send http request
        //
        dwStatus = HttpsSendRequest(Socket,
            phCreds,
            phContext,
            pszFileName,
            pQuicApplicationKeys);
        if (WEBCLI_ERROR_SUCCESS != dwStatus)
        {
            printf("- EarlyStart HttpsSendRequest failed!\n");
            return dwStatus;
        }

        printf("- EarlyStart HttpsSendRequest sent. Not waiting for Response!\n");

        g_fEarlyStartGetSent = TRUE;

        return dwStatus;
    }

    //
    // send http request
    //
    dwStatus = HttpsSendRequest(Socket,
        phCreds,
        phContext,
        pszFileName,
        pQuicApplicationKeys);
    if (WEBCLI_ERROR_SUCCESS != dwStatus)
    {
        printf("- HttpsSendRequest failed to send Request!\n");
        return dwStatus;
    }

    //
    // Allocate a working buffer based on sizes for stream/connection mode
    //

    // stream mode
    cbIoBufferLength = pvSizesStream.cbHeader +
        pvSizesStream.cbMaximumMessage +
        pvSizesStream.cbTrailer;

    // the actual allocation after the size fixed above
    pbIoBuffer = (PBYTE)LocalAlloc(LPTR, cbIoBufferLength);
    if (pbIoBuffer == NULL)
    {
        printf("- Allocation of pbIoBuffer failed, Out of memory!\n");
        dwStatus = WEBCLI_ERROR_ERROR;
        goto cleanup;
    }

    // for holding the header
    pbHeader = (PBYTE)LocalAlloc(LPTR, MYMAX_BUFFER_LENGTH);
    if (pbHeader == NULL)
    {
        printf("- Allocation of pbHeader failed, Out of memory!\n");
        dwStatus = WEBCLI_ERROR_ERROR;
        goto cleanup;
    }

    if (pExtraData && pExtraData->pvBuffer)
    {
        if (pExtraData->cbBuffer > cbIoBufferLength)
        {
            printf("- pExtraData should not be more than pbIoBuffer!\n");
            dwStatus = WEBCLI_ERROR_ERROR;
            goto cleanup;
        }
        RtlCopyMemory(pbIoBuffer, pExtraData->pvBuffer, pExtraData->cbBuffer);
        cbIoBuffer = pExtraData->cbBuffer;
    }
    else
    {
        cbIoBuffer = 0;
    }

    // Loop until all application data has been received and cbIoBuffer has been processed completely.
    do
    {
        BOOL fEmptyAppDataReceived = FALSE;
        // Read a packet from the server.
        dwStatus = SslReadPacket(
            Socket,
            phContext,
            pbIoBuffer,
            cbIoBufferLength,
            &cbIoBuffer,
            &pbExtra,
            &cbExtra,
            pQuicApplicationKeys,
            &fEmptyAppDataReceived);
        //shouldn't append extra data, because that's done below

        if (dwStatus != SEC_E_OK && dwStatus != SEC_I_RENEGOTIATE)
        {
            printf("- SslReadPacket failed with 0x%lx\n", dwStatus);
            goto cleanup;
        }


        // server wants client auth, renegotiation required
        if (dwStatus == SEC_I_RENEGOTIATE)
        {
            // The server wants to perform another handshake sequence.
            printf("- Server requested renegotiation!\n");

            ExtraBuffer.pvBuffer = pbExtra,
                ExtraBuffer.cbBuffer = cbExtra;

            dwStatus = ClientHandshakeLoop(
                Socket,
                phCreds,
                phContext,
                FALSE,
                &ExtraBuffer,
                NULL,
                NULL);

            if (dwStatus != SEC_E_OK)
            {
                printf("- Renegotiation Handshake failed!\n");
                goto cleanup;
            }

            // Move any "extra" data to the input buffer.
            if (ExtraBuffer.pvBuffer)
            {
                MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                cbIoBuffer = ExtraBuffer.cbBuffer;
                LocalFree(ExtraBuffer.pvBuffer);
                ExtraBuffer.pvBuffer = NULL;
                ExtraBuffer.cbBuffer = 0;
            }
            continue;
        }

        // Display or otherwise process the decrypted data
        // received from SslReadPacket
        if (cbIoBuffer ||
            // Only accept zero length appdata if it was expected.
            fEmptyAppDataReceived)
        {
            printf("- Received %d bytes plaintext.\n", cbIoBuffer);
            PrintHexDump(cbIoBuffer, pbIoBuffer);

            // parse the HTTP Response header
            if (fHeader)
            {
                PBYTE pbEndHeader;
                PCHAR pszContentLength;

                MoveMemory(pbHeader + cbHeader, pbIoBuffer, min(cbIoBuffer, MYMAX_BUFFER_LENGTH - cbHeader));
                cbHeader += cbIoBuffer;
                pbHeader[min(cbHeader, MYMAX_BUFFER_LENGTH - 1)] = '\0';
                cbContentRead += cbIoBuffer;

                // check if entire HTTP Response header has been received
                if (NULL == strstr((LPSTR)pbHeader, "\r\n\r\n"))
                {
                    printf("- Complete HTTP Response Header not received, fetch more.\n");

                    // Move any "extra" data to the input buffer.
                    if (pbExtra)
                    {
                        MoveMemory(pbIoBuffer, pbExtra, cbExtra);
                        cbIoBuffer = cbExtra;
                    }
                    else
                    {
                        cbIoBuffer = 0;
                    }

                    continue;
                }

                // entire HTTP Response header received, parse it
                if ((strstr((LPSTR)pbHeader, "HTTP/1.0 200") == NULL) &&
                    (strstr((LPSTR)pbHeader, "HTTP/1.1 200") == NULL)
                    )
                {
                    // HTTP error received.
                    pbEndHeader = (PBYTE)strstr((LPCSTR)pbHeader, "\r\n");
                    *pbEndHeader = '\0';
                    printf("**** %s\n", pbHeader);
                    dwStatus = WEBCLI_ERROR_ERROR;
                    goto cleanup;
                }

                // Read content length parameter.
                pszContentLength = strstr((PCHAR)pbHeader, "Content-Length:");
                if (pszContentLength == NULL)
                {
                    pszContentLength = strstr((PCHAR)pbHeader, "Content-length:");
                }
                if (pszContentLength)
                {
                    pszContentLength += strlen("Content-Length:");
                    dwContentLength = atol(pszContentLength);
                }
                else
                {
                    printf("- No content length in header!\n");
                    dwContentLength = 0;
                }

                // Skip over the http header.
                pbEndHeader = (PBYTE)strstr((LPCSTR)pbHeader, "\r\n\r\n");
                if (pbEndHeader)
                {
                    pbEndHeader += 4;
                    cbHeader = (DWORD)(pbEndHeader - pbHeader);
                }

                cbContentRead -= cbHeader;
                fHeader = FALSE;
            }
            else if (cbContentRead < dwContentLength)
            {
                cbContentRead += cbIoBuffer;
            }

        }

        // Move any "extra" data to the input buffer.
        if (pbExtra != NULL)
        {
            MoveMemory(pbIoBuffer, pbExtra, cbExtra);
            cbIoBuffer = cbExtra;
        }

        // check if we've read all application data
        if (cbContentRead == dwContentLength)
        {
            printf("- All application data received.\n");
        }

        if (cbContentRead > dwContentLength)
        {
            printf("- %d bytes of extra plaintext received!\n",
                cbContentRead - dwContentLength);
        }

    } while (fHeader ||
        cbContentRead < dwContentLength ||
        cbIoBuffer != 0);



    dwStatus = SEC_E_OK;
cleanup:
    if (NULL != pbIoBuffer)
    {
        DbglibLocalFree(pbIoBuffer);
        pbIoBuffer = NULL;

    }
    if (NULL != pbHeader)
    {
        DbglibLocalFree(pbHeader);
        pbHeader = NULL;
    }

    return dwStatus;

} // end HttpsGetFile()

/*********************************************************************
 Sends HTTP Request
*********************************************************************/
unsigned long
HttpsSendRequest(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN     CtxtHandle* phContext,
    IN     LPSTR           pszFileName,
    IN     PQUIC_KEYS      pQuicApplicationKeys)
{
    DWORD           dwStatus = WEBCLI_ERROR_SUCCESS;
    SecBufferDesc   Message = { 0 };
    SecBuffer       Buffers[5] = { 0 };
    SecBuffer       ExtraBuffer = { 0 };

    PBYTE           pbIoBuffer = NULL;
    DWORD           cbIoBufferLength = 0;
    PBYTE           pbHeader = NULL;
    DWORD           cbHeader = 0;
    PBYTE           pbReqMessage = NULL;
    DWORD           cbReqMessage = 0;
    PBYTE           pbTrailer = 0;
    DWORD           cbTrailer = 0;
    DWORD           cbDataSent = 0;
    BYTE            rgbAlert[256] = { 0 };
    INT             i = 0;
    BOOL bSendZeroLengthApplicationData = 0;

    //
    // Allocate a working buffer based on sizes for stream/connection mode
    //

// stream mode
    cbIoBufferLength = pvSizesStream.cbHeader +
        pvSizesStream.cbMaximumMessage +
        pvSizesStream.cbTrailer;

    // the actual allocation after the size fixed above
    pbIoBuffer = (PBYTE)LocalAlloc(LPTR, cbIoBufferLength);
    if (pbIoBuffer == NULL)
    {
        printf("- Allocation of pbIoBuffer failed, Out of memory!\n");
        dwStatus = WEBCLI_ERROR_ERROR;
        goto cleanup;
    }

    // Build the HTTP request offset into the data buffer by "header size"
    // bytes. This enables Schannel to perform the encryption in place,
    // which is a significant performance win.
    pbHeader = pbIoBuffer;
    cbHeader = pvSizesStream.cbHeader;
    pbReqMessage = pbIoBuffer + pvSizesStream.cbHeader;

    bSendZeroLengthApplicationData = FALSE;
    while (TRUE) // While we have more data to send
    {
        if (bSendZeroLengthApplicationData)
        {
            // Send Zero length app data by setting send size to 0.
            // this is done before sending the request.
            cbReqMessage = 0;
        }
        else
        {
            //
            // Build an HTTP request to send to the server.
            //

            // Remove the trailing backslash from the filename, should one exist.
            if (pszFileName && strlen(pszFileName) > 1 &&
                pszFileName[strlen(pszFileName) - 1] == '/')
            {
                pszFileName[strlen(pszFileName) - 1] = 0;
            }
            // Build HTTP request.
            // Note: Assuming that this is less than the maximum message size.
            //       If it weren't, it would have to be broken up.
            sprintf((PCHAR)pbReqMessage,
                "GET /%s HTTP/1.1\r\nUser-Agent: Webclient\r\n"
                "Accept:*/*\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n",
                pszFileName, g_pszServerName);
            printf("- HTTP Request: \n%s\n", pbReqMessage);

            cbReqMessage = strlen((PCHAR)pbReqMessage);
        }

        printf("- Encrypt and Send %d bytes plaintext.", cbReqMessage);
        printf("- Plaintext data buffer:\n");
        PrintHexDump(cbReqMessage, pbReqMessage);

        //set Trailer location for contiguous buffer
        pbTrailer = pbReqMessage + cbReqMessage;

        cbTrailer = pvSizesStream.cbTrailer;

        //
        // Construct the message buffers for the HTTP Request
        //

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        Buffers[0].pvBuffer = pbHeader;
        Buffers[0].cbBuffer = cbHeader;
        Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        Buffers[1].pvBuffer = pbReqMessage;
        Buffers[1].cbBuffer = cbReqMessage;
        Buffers[1].BufferType = SECBUFFER_DATA;

        Buffers[2].pvBuffer = pbTrailer;
        Buffers[2].cbBuffer = cbTrailer;
        Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        Buffers[3].BufferType = SECBUFFER_ALERT;
        Buffers[3].cbBuffer = 255;
        Buffers[3].pvBuffer = rgbAlert;
        Buffers[4].BufferType = SECBUFFER_EMPTY;

        // Encrypt the HTTP Request Message
        dwStatus = EncryptMessage(phContext, 0, &Message, 0);

        //
        // Check if an Alert was generated, very rare
        //
        if (Buffers[3].cbBuffer != 0 &&
            Buffers[3].pvBuffer != NULL &&
            dwStatus != SEC_E_OK)
        {
            printf("An ALERT was generated from EncryptMessage\n");
            PrintHexDump(Buffers[3].cbBuffer, (PBYTE)Buffers[3].pvBuffer);
        }

        if (FAILED(dwStatus))
        {
            printf("- Error 0x%x returned by EncryptMessage!\n", dwStatus);
            goto cleanup;
        }

        printf("- EncryptMessage succeeded with 0x%lx.\n", dwStatus);

        //
        // Send the encrypted data to the server.
        //
        cbDataSent = send(
            Socket,
            (PCHAR)pbIoBuffer,
            Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
            0);
        g_dwNumServerSends++;

        if (cbDataSent == SOCKET_ERROR || cbDataSent == 0)
        {
            dwStatus = WSAGetLastError();
            printf("- Error %d sending data to server!\n", dwStatus);
            if (phContext)
            {
                DeleteSecurityContext(phContext);
            }
            goto cleanup;
        }

        printf("- %d bytes of encrypted application data sent.\n", cbDataSent);
        printf("- Sent encrypted app data buffer:\n");
        PrintHexDump(cbDataSent, pbIoBuffer);

        if (bSendZeroLengthApplicationData)
        {
            bSendZeroLengthApplicationData = FALSE;
            // Now send the actual request.
            continue;
        }

        break;
    }


cleanup:
    if (NULL != pbIoBuffer)
    {
        LocalFree(pbIoBuffer);
        pbIoBuffer = NULL;
    }

    return dwStatus;

}


/*********************************************************************
 Reads data from socket, Decrypts and handles the received data
 pbBuffer - recv and DecryptMessage will be done on this buffer. Owned by Caller.
 ppbExtra - *ppbExtra will point to somewhere in pbBuffer. Owned by caller.
*********************************************************************/
unsigned long
SslReadPacket(
    IN     SOCKET      Socket,
    IN     CtxtHandle* phContext,
    IN OUT PBYTE       pbBuffer,       // input\output buffer
    IN     DWORD       cbBuffer,       // size of buffer
    IN OUT DWORD* pcbDataRead,    // in\out data read
    OUT PBYTE* ppbExtra,       // out extra data buffer
    OUT DWORD* pcbExtra,       // out extra data bytes
    IN     PQUIC_KEYS  pQuicApplicationKeys,
    // For caller to detect whether we received an empty application data
    // buffer (vs reading 0 bytes of data from socket indicating connection close)
    OUT    PBOOL       pfRecievedEmptyMessage)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    SecBufferDesc   Message = { 0 };
    SecBuffer       Buffers[5] = { 0 };
    SecBuffer* pDataBuffer = NULL;
    SecBuffer* pExtraBuffer = NULL;
    DWORD           cbData = 0;
    DWORD           cbDataRead = *pcbDataRead;
    ULONG           i = 0;
    BYTE            rgbAlert[256] = { 0 };
    LARGE_INTEGER      sPerformanceCountBegin = { 0 };
    LARGE_INTEGER      sPerformanceCountEnd = { 0 };
    LARGE_INTEGER      sCountElapsed = { 0 };
    LARGE_INTEGER g_sHighResolutionFrequency = { 0 };
    //FILE* hstream = NULL;

    if (NULL != pfRecievedEmptyMessage)
    {
        *pfRecievedEmptyMessage = FALSE;
    }

    while (TRUE)
    {
        //
        // Read some data if necessary.
        //

        if (cbDataRead == 0 || dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (cbBuffer == 0)
            {
                // Input buffer is too small to hold packet.
                return SEC_E_BUFFER_TOO_SMALL;
            }

            // Receive data from the server over the socket.
            DWORD cbRemainingBuffer = min(IO_BUFFER_SIZE, cbBuffer - cbDataRead);
            // For connection mode we only want to read one record at a time.
            DWORD cbTempBuffer = cbRemainingBuffer;

            PBYTE pbTempBuffer = pbBuffer + cbDataRead;
            cbData = recv(
                Socket,
                (LPSTR)pbTempBuffer,
                cbTempBuffer,
                0);

            if (cbData == SOCKET_ERROR)
            {
                dwStatus = WSAGetLastError();
                printf("- Error %d reading data from server!\n", dwStatus);
                return dwStatus;
            }

            if (cbData == 0)
            {
                if (cbDataRead)
                {
                    // Already read some data and then Server disconnected?!
                    printf("- Server unexpectedly disconnected!\n");
                    return WEBCLI_ERROR_ERROR;
                }
                else
                {
                    // received nothing?!
                    *pcbDataRead = 0;
                    *ppbExtra = NULL;
                    *pcbExtra = 0;
                    printf("- Something is not right. Returning ERROR!\n");
                    return WEBCLI_ERROR_ERROR;
                }
            }

            printf("- %d bytes of encrypted application data received.\n", cbData);
            printf("- Received encrypted application data buffer:\n");
            PrintHexDump(cbData, pbBuffer + cbDataRead);

            cbDataRead += cbData;
        } //  if(cbDataRead == 0 || dwStatus == SEC_E_INCOMPLETE_MESSAGE)

        //
        // Attempt to decrypt the received data.
        //
        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 5;
        Message.pBuffers = Buffers;

        // stream mode
        Buffers[0].BufferType = SECBUFFER_DATA;
        Buffers[0].pvBuffer = pbBuffer;
        Buffers[0].cbBuffer = cbDataRead;

        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;

        //
        // We need 3 empty buffers passed in for stream mode for
        // header, trailer and extra buffers.
        //

        Buffers[3].BufferType = SECBUFFER_EMPTY;
        Buffers[4].BufferType = SECBUFFER_ALERT;
        Buffers[4].cbBuffer = 255;
        Buffers[4].pvBuffer = rgbAlert;



        // Decrypt Data
        dwStatus = DecryptMessage(
            phContext,
            &Message,
            0,
            NULL);



        printf("- DecryptMessage returned 0x%lx\n", dwStatus);

        // more data needed, loopback
        if (dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more data.
            printf("- DecryptMessage returned SEC_E_INCOMPLETE_MESSAGE\n");

            for (i = 0; i < Message.cBuffers; i++)
            {
                BOOL fFoundMissing = FALSE;

                switch (Buffers[i].BufferType)
                {
                case SECBUFFER_MISSING:
                    fFoundMissing = TRUE;
                    printf("- Type- %d = SECBUFFER_MISSING.\n", Buffers[i].BufferType);
                    printf("- %d bytes of missing data.\n", Buffers[i].cbBuffer);
                    break;

                default:
                    break;
                }

                if (fFoundMissing)
                    break;
            }

            // loop
            continue;
        }

        // server wants client authentication or refresh keys
        if (dwStatus == SEC_I_RENEGOTIATE)
        {
            printf("- DecryptMessage returned SEC_I_RENEGOTIATE\n");
        }

        // error case
        if (dwStatus != SEC_E_OK &&
            dwStatus != SEC_I_RENEGOTIATE &&
            dwStatus != SEC_I_CONTEXT_EXPIRED
            )
        {
            if (Buffers[4].BufferType == SECBUFFER_ALERT && Buffers[4].cbBuffer != 0)
            {
                // We have an alert

                printf("- DecryptMessage generated an ALERT MESSAGE\n");
                PrintHexDump(Buffers[4].cbBuffer, (PBYTE)Buffers[4].pvBuffer);


            }

            printf("- Error 0x%x returned by DecryptMessage!\n", dwStatus);
            return dwStatus;
        }

        // Locate data and (optional) extra buffers.
        pDataBuffer = NULL;
        pExtraBuffer = NULL;
        for (i = 0; i < Message.cBuffers; i++)
        {
            switch (Buffers[i].BufferType)
            {
            case SECBUFFER_DATA:
                printf("- Type- %d = SECBUFFER_DATA.\n", Buffers[i].BufferType);
                printf("- %d bytes of ciphertext data decrypted.\n", Buffers[i].cbBuffer);
                if (NULL == pDataBuffer)
                {
                    pDataBuffer = &Buffers[i];
                    printf("- SECBUFFER_DATA buffer:\n");
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }
                else
                {
                    printf("- pDataBuffer in not NULL?\n");
                }
                break;


            case SECBUFFER_EXTRA:
                printf("- Type- %d = SECBUFFER_EXTRA.\n", Buffers[i].BufferType);
                printf("- %d bytes of leftover extra bytes.\n", Buffers[i].cbBuffer);
                if (NULL == pExtraBuffer)
                {
                    pExtraBuffer = &Buffers[i];
                    printf("- SECBUFFER_EXTRA buffer:\n");
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }
                else
                {
                    printf("- pExtraBuffer in not NULL?\n");
                }


                break;

            case SECBUFFER_TOKEN:
                printf("- Type- %d = SECBUFFER_TOKEN.\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted TOKEN data.\n", Buffers[i].cbBuffer);
                printf("- SECBUFFER_TOKEN buffer:\n");
                PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                break;

            case SECBUFFER_EMPTY:
                printf("- Type- %d = SECBUFFER_EMPTY.\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted empty data.\n", Buffers[i].cbBuffer);
                break;

            case SECBUFFER_ALERT:
                printf("- Type- %d = SECBUFFER_ALERT.\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted alert data.\n", Buffers[i].cbBuffer);
                break;

            case SECBUFFER_STREAM_HEADER:
                printf("- Type- %d = SECBUFFER_STREAM_HEADER\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted header data.", Buffers[i].cbBuffer);
                printf("- SECBUFFER_STREAM_HEADER buffer:\n");
                PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                break;

            case SECBUFFER_STREAM_TRAILER:
                printf("- Type- %d = SECBUFFER_STREAM_TRAILER\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted trailer data.\n", Buffers[i].cbBuffer);
                printf("- SECBUFFER_STREAM_TRAILER buffer:\n");
                PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                break;

            case SECBUFFER_MISSING:
                printf("- Type- %d = SECBUFFER_MISSING.\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted missing data.\n", Buffers[i].cbBuffer);
                if (NULL != Buffers[i].pvBuffer)
                {
                    printf("- SECBUFFER_MISSING buffer:\n");
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }

                //
                // Check if the buffer missing buffer actually has a
                // value in the cbBuffer field.
                //
                if (Buffers[i].cbBuffer == 0)
                {
                    printf(" - Decrypt returned SECBUFFER_MISSING but cbValue field of the buffer was 0\n");
                    dwStatus = MYDBG_ERROR_ERROR;
                    goto Cleanup;
                }

                break;

            default:
                printf(": UKNOWN Buffer Type %d\n", Buffers[i].BufferType);
                printf("- %d bytes of decrypted UNKNOWN data.\n", Buffers[i].cbBuffer);
                break;
            } // switch
        } // for(buffers)

        //
        // Fill in output parameters.
        //
        MoveMemory(pbBuffer, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);

        *pcbDataRead = pDataBuffer->cbBuffer;

        if (pExtraBuffer)
        {
            *ppbExtra = pbBuffer + cbDataRead - pExtraBuffer->cbBuffer;
            *pcbExtra = pExtraBuffer->cbBuffer;
        }
        else
        {
            *ppbExtra = NULL;
            *pcbExtra = 0;
        }

        if (NULL != pfRecievedEmptyMessage && pDataBuffer->cbBuffer == 0)
        {
            // Indicate to the caller that we received an empty buffer after decryption.
            *pfRecievedEmptyMessage = TRUE;
        }

        break;
    } // while(TRUE)

Cleanup:
    return dwStatus;
} // end SslReadPacket()

/********************************************************************
    Cases:  CLIENT_AUTH_AUTOMATIC     ||
            CLIENT_AUTH_MANUAL        ||
            CLIENT_AUTH_PICKLED_CRED  ||
            CLIENT_AUTH_MEMORY_STORE  ||
            CLIENT_AUTH_CALL_CAQ
********************************************************************/
DWORD
CreateClientCredentials(
    __in_opt LPSTR pszUserName,
    __in_opt LPSTR pszPfxPath,
    __inout PCredHandle phCreds)
{
    DWORD                        dwStatus = WEBCLI_ERROR_ERROR;
    TimeStamp                    tsExpiry = { 0 };
    union
    {
        SCHANNEL_CRED v4;
        SCH_CREDENTIALS v5;
    } SchannelCred = { 0 };

    // cred version
    SchannelCred.v4.dwVersion = SCHANNEL_CRED_VERSION;

    HCERTSTORE                   hMyCertStore = NULL;
    PCCERT_CONTEXT               pCertContext = NULL;
    HCERTSTORE                   hMemoryStore = NULL;

    LPSTR                        PickledCert = NULL;
    DWORD                        dwHashLength = 0;
    CERT_CREDENTIAL_INFO         CertCredInfo = { 0 };
    SEC_WINNT_AUTH_IDENTITY_EXA  ClientAuthID = { 0 };

    CRYPT_KEY_PROV_INFO* pCryptKeyProvInfo = NULL;
    TLS_PARAMETERS               tlsParameters = { 0 };
    SCHANNEL_CERT_HASH           kModeCertHash = { sizeof(SCHANNEL_CERT_HASH), 0, 0, {0} };

    //
    // set appropriate SchannelCred flag
    //
    {
        //
        // set the flag to manual and then find the client certificate
        //
        printf("- webcli will pick client cert manually\n");
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        }

        //
        // Open the "MY" certificate store, which is where
        // Internet Explorer stores its client certificates.
        //
        if (pszPfxPath == NULL)
        {
            hMyCertStore = CertOpenSystemStore(0, "MY");

            if (!hMyCertStore)
            {
                dwStatus = GetLastError();
                printf("- Error 0x%x returned by CertOpenSystemStore!\n", dwStatus);
                return dwStatus;
            }
        }
        else
        {
            dwStatus = ReadPfxStore(pszPfxPath, &hMyCertStore);
            if (dwStatus != ERROR_SUCCESS)
            {
                printf("- Error 0x%x ReadPfxStore failed!\n", dwStatus);
                goto cleanup;
            }
        }

        //
        // If a user name is specified, then attempt to find a client
        // certificate. Otherwise, just create a NULL credential.
        // used by manual, pickled and memory store
        //

        if (pszUserName != NULL)
        {
            // Find client certificate. Note that this sample just searchs
            // for a certificate that contains the user name somewhere in
            // the subject name.
            // A real application should be a bit less casual.
            pCertContext = CertFindCertificateInStore(
                hMyCertStore,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_STR_A,
                pszUserName,
                NULL);
            if (NULL == pCertContext)
            {
                dwStatus = GetLastError();
                printf("- Error 0x%x returned by CertFindCertificateInStore!\n", dwStatus);
                goto cleanup;
            }
            else
            {
                printf("- Found client cert using supplied user name. CRYPT_ALGORITHM_IDENTIFIER is: %s\n",
                    pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);
            }
        }
        else if (pszPfxPath != NULL)
        {
            pCertContext = FindFirstCertContextWithKey(hMyCertStore);
            if (pCertContext == NULL)
            {
                dwStatus = GetLastError();
                printf("- Error 0x%x FindFirstCertContextWithKey failed!\n", dwStatus);
                goto cleanup;
            }
        }


        //===================================================================
        // Call CryptAcquireContext
        // HACK for repro'ing the wireless scenario: should put more thought
        //===================================================================



    } // else (MANUAL || PICKLED_CERT || MEMORY_STORE)

    //
    // Build Schannel credential structure. Currently, this sample only
    // specifies the protocol to be used (and optionally the certificate,
    // of course). Real applications may wish to specify other parameters
    // as well.
    //

    if (pCertContext != NULL)
    {
        DWORD cbHash = sizeof(kModeCertHash.ShaHash);
        if (!CertGetCertificateContextProperty(
            pCertContext,
            CERT_HASH_PROP_ID,
            kModeCertHash.ShaHash,
            &cbHash))
        {
            dwStatus = GetLastError();
            printf("- Error 0x%x reading Certificate hash property!\n", dwStatus);
            goto cleanup;
        }
    }

    if (pCertContext)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.cCreds = 1;
            SchannelCred.v4.paCred = &pCertContext;
        }
        else
        {
            SchannelCred.v5.cCreds = 1;
            SchannelCred.v5.paCred = &pCertContext;
        }
    }

    if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
    {
        SchannelCred.v4.grbitEnabledProtocols = 0;


    }
    else
    {
        if (SchannelCred.v5.cTlsParameters > 0)
        {
            // The last parameter in the blacklist will hold the protocol version(s) blacklisted.
            SchannelCred.v5.pTlsParameters[SchannelCred.v5.cTlsParameters - 1].grbitDisabledProtocols = 0;
        }
        else
        {
            tlsParameters.grbitDisabledProtocols = 0;
            SchannelCred.v5.pTlsParameters = &tlsParameters;
            SchannelCred.v5.cTlsParameters = 1;
        }
    }

    //
    // Create an SSPI credential.
    //
    dwStatus = AcquireCredentialsHandleA(
        NULL,                   // Name of principal
        (LPSTR)UNISP_NAME,    // Name of package
        SECPKG_CRED_OUTBOUND,   // Flags indicating use
        NULL,                   // Pointer to logon ID
        (PVOID)&SchannelCred,   // Package specific data
        NULL,                   // Pointer to GetKey() func
        NULL,                   // Value to pass to GetKey()
        phCreds,                // (out) Cred Handle
        &tsExpiry);             // (out) Lifetime (optional)

    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x returned by AcquireCredentialsHandle!\n", dwStatus);
        goto cleanup;
    }

    printf("- ACH succeeded.\n");

cleanup:
    //
    // Free the certificate context. Schannel has already made its own copy.
    //

    if (pCertContext)
    {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    if (NULL != pCryptKeyProvInfo)
    {
        DbglibLocalFree(pCryptKeyProvInfo);
        pCryptKeyProvInfo = NULL;
    }

    // Close memory certificate store.
    if (hMemoryStore)
    {
        CertCloseStore(hMemoryStore, 0);
        hMemoryStore = NULL;
    }
    // Close "MY" certificate store.
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
        hMyCertStore = NULL;
    }

    return dwStatus;
} // CreateClientCredentials()

DWORD
ReadPfxStore(
    _In_ LPSTR pszPfxPath,
    _Out_ HCERTSTORE* phPfxCertStore)
{
    PBYTE pbPfxStore = NULL;
    HCERTSTORE hPfxCertStore = NULL;

    if (phPfxCertStore == NULL || pszPfxPath == NULL)
    {
        return SEC_E_INVALID_PARAMETER;
    }

    DWORD dwStatus = SEC_E_INTERNAL_ERROR;
    HANDLE hPfxFile = CreateFile(pszPfxPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hPfxFile == INVALID_HANDLE_VALUE)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by CreateFile!\n", dwStatus);
        return dwStatus;
    }

    DWORD cbPfxStore = GetFileSize(hPfxFile, NULL);
    if (cbPfxStore == INVALID_FILE_SIZE)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by GetFileSize!\n", dwStatus);
        goto cleanup;
    }

    pbPfxStore = (PBYTE)DbglibLocalAlloc(cbPfxStore);
    if (pbPfxStore == NULL)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by LocalAlloc!\n", dwStatus);
        goto cleanup;
    }

    DWORD dwBytesRead;
    ReadFile(hPfxFile, pbPfxStore, cbPfxStore, &dwBytesRead, NULL);
    if (dwBytesRead != cbPfxStore)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by ReadFile!\n", dwStatus);
        goto cleanup;
    }

    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = cbPfxStore;
    pfxBlob.pbData = pbPfxStore;

    hPfxCertStore = PFXImportCertStore(&pfxBlob, L"", PKCS12_NAMED_NO_PERSIST_KEY | PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP);
    if (hPfxCertStore == NULL)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by PFXImportCertStore!\n", dwStatus);
        goto cleanup;
    }

    *phPfxCertStore = hPfxCertStore;
    hPfxCertStore = NULL;
    dwStatus = ERROR_SUCCESS;

cleanup:
    if (hPfxCertStore != NULL)
    {
        CertCloseStore(hPfxCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
    }

    if (pbPfxStore != NULL)
    {
        DbglibLocalFree(pbPfxStore);
    }

    if (hPfxFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPfxFile);
    }

    return dwStatus;
}


/////////////////////////////////////////////////////////////////////////////
//  Function: FindFirstCertContextWithKey()
//  Purpose: Helper function to find the first certificate context with a key.
//  Return value must be freed with CertFreeCertificateContext if non null.
/////////////////////////////////////////////////////////////////////////////
PCCERT_CONTEXT FindFirstCertContextWithKey(_In_ HCERTSTORE hStore)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fFound = FALSE;

    // Note that CertEnumCertificatesInStore frees the previous certificate context.
    while (!fFound && (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)))
    {
        BOOL fShouldFree = FALSE;
        DWORD dwKeySpec = 0;
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
        fFound = CryptAcquireCertificatePrivateKey(
            pCertContext,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_SILENT,
            NULL,
            &hCryptProvOrNCryptKey,
            &dwKeySpec,
            &fShouldFree);
        if (fShouldFree && hCryptProvOrNCryptKey != 0)
        {
            if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
            {
                NCryptFreeObject(hCryptProvOrNCryptKey);
            }
            else
            {
                CryptReleaseContext(hCryptProvOrNCryptKey, 0);
            }
        }
    }

    return pCertContext;
}

//++----------------------------------------------------------------------
//  NAME:  QueryContextWrapper
//  
//  DESC:  wrpas the QueryContextAttributes calls
//  
//  ARGUMENTS: 
//  - DWORD dwAttr : attribute to query
//  - PCtxtHandle  : context handle (useless here)
//
//  RETURNS:   
//  - DWORD: status code
//  
//  NOTE:      
//--------------------------------------------------------------------++//
DWORD
QueryContextWrapper(
    IN     DWORD       dwAttr,
    IN     PCtxtHandle phContext
)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;
    DWORD  dwQueryAttr = dwAttr;
    PVOID  pvBuffer = NULL;
    ULONG  dwMemSize = 0;
    PSecPkgContext_ConnectionInfo   pConnInfo = NULL;
    PSecPkgContext_StreamSizes      pStreamSizes = NULL;
    PSecPkgContext_Sizes            pConnSizes = NULL;
    PSecPkgContext_IssuerListInfoEx pIssrListEx = NULL;
    PCCERT_CONTEXT                  pRemoteCert = NULL;
    PCCERT_CONTEXT                  pLocalCert = NULL;
    PSecPkgContext_SessionInfo      pSessInfo = NULL;
    PSecPkgContext_KeyInfo          pKeyInfo = NULL;
    PSecPkgContext_ProtoInfo        pProtoInfo = NULL;
    PSecPkgContext_EapKeyBlock      pEapKeyBlock = NULL;
    PSecPkgContext_Certificates     pRemoteKCerts = NULL;
    PSecPkgContext_CertInfo         pLclCertInfo = NULL;
    PSecPkgContext_SessionKey       pSessKey = NULL;
    PSecPkgContext_ClientCertPolicyResult pCliCertPolicyRes = NULL;
    PSecPkgContext_ApplicationProtocol    pApplicationProtocol = NULL;

    CHAR   pcProtocolIdStr[MAX_PROTOCOL_ID_SIZE + 1] = { 0 };


    //=======================================================================    
    // figure out how much memory to allocate and allocate it
    //=======================================================================    
    switch (dwAttr)
    {
    case SECPKG_ATTR_CONNECTION_INFO:
        dwMemSize = sizeof(SecPkgContext_ConnectionInfo);
        break;
    case SECPKG_ATTR_STREAM_SIZES:
        dwMemSize = sizeof(SecPkgContext_StreamSizes);
        break;
    case SECPKG_ATTR_SIZES:
        dwMemSize = sizeof(SecPkgContext_Sizes);
        break;
    case SECPKG_ATTR_ISSUER_LIST_EX:
        dwMemSize = sizeof(SecPkgContext_IssuerListInfoEx);
        break;
    case SECPKG_ATTR_REMOTE_CERT_CONTEXT:
        pvBuffer = (PVOID)&pRemoteCert;
        dwMemSize = 0;
        break;
    case SECPKG_ATTR_LOCAL_CERT_CONTEXT:
        pvBuffer = (PVOID)&pLocalCert;
        dwMemSize = 0;
        break;
    case SECPKG_ATTR_SESSION_INFO:
        dwMemSize = sizeof(SecPkgContext_SessionInfo);
        break;
    case SECPKG_ATTR_KEY_INFO:
        dwMemSize = sizeof(SecPkgContext_KeyInfo);
        break;
    case SECPKG_ATTR_PROTO_INFO:
        dwMemSize = sizeof(SecPkgContext_ProtoInfo);
        break;
    case SECPKG_ATTR_EAP_KEY_BLOCK:
        dwMemSize = sizeof(SecPkgContext_EapKeyBlock);
        break;
    case SECPKG_ATTR_REMOTE_CERTIFICATES:
        dwMemSize = sizeof(SecPkgContext_Certificates);
        break;
    case SECPKG_ATTR_LOCAL_CERT_INFO:
        dwMemSize = sizeof(SecPkgContext_CertInfo);
        break;
    case SECPKG_ATTR_SESSION_KEY:
        dwMemSize = sizeof(SecPkgContext_SessionKey);
        break;
    case SECPKG_ATTR_CC_POLICY_RESULT:
        dwMemSize = sizeof(SecPkgContext_ClientCertPolicyResult);
        break;
    case SECPKG_ATTR_APPLICATION_PROTOCOL:
        dwMemSize = sizeof(SecPkgContext_ApplicationProtocol);
        break;
    case SECPKG_ATTR_CONNECTION_INFO_EX:
        dwMemSize = sizeof(SecPkgContext_ConnectionInfoEx);
        break;

    default:
        printf("- Attribute not supported.\n");
        break;
    }

    // allocate memory for the buffer
    if (dwMemSize) // hack for PCCERT_CONTEXT
    {
        pvBuffer = DbglibLocalAlloc(dwMemSize);
        if (NULL == pvBuffer)
        {
            dwStatus = MYDBG_ERROR_OUTOFMEMORY;
            printf("- Memory allocation for pBuffer FAILED!\n");
            goto cleanup;
        }
    }

    //=======================================================================    
    // call QueryContextAttributes
    //=======================================================================    

    printf("- Calling user QCA with attribute ID 0x%x\n", dwAttr);
    dwStatus = QueryContextAttributes(
        phContext,
        dwAttr,
        pvBuffer);

    if (SEC_E_OK != dwStatus)
    {
        // all attributes should succeed in user mode
        printf("- QueryContextAttributes FAILED!\n");
        goto cleanup;
    }
    else
    {
        printf("- QContextA succeeded for attribute ID 0x%x\n", dwAttr);
    }

    //=======================================================================
    // print useful info for each attribute
    //=======================================================================
    // dwAttr = dwQueryAttr;
    switch (dwAttr)
    {
    case SECPKG_ATTR_CONNECTION_INFO:
        pConnInfo = (PSecPkgContext_ConnectionInfo)pvBuffer;
        printf("- SECPKG_ATTR_CONNECTION_INFO:\n");
        DisplayConnectionInfo(pConnInfo);
        break;

    case SECPKG_ATTR_STREAM_SIZES:
        pStreamSizes = (PSecPkgContext_StreamSizes)pvBuffer;
        printf("- SECPKG_ATTR_STREAM_SIZES:\n");
        printf("\t Header: %d, Trailer: %d, MaxMessage: %d\n",
            pStreamSizes->cbHeader,
            pStreamSizes->cbTrailer,
            pStreamSizes->cbMaximumMessage);
        break;

    case SECPKG_ATTR_SIZES:
        pConnSizes = (PSecPkgContext_Sizes)pvBuffer;
        printf("- SECPKG_ATTR_SIZES:\n");
        printf("\t Block Size: %d, MaxToken: %d\n\t SecurityTrailer: %d, MaxSignature: %d",
            pConnSizes->cbBlockSize,
            pConnSizes->cbMaxToken,
            pConnSizes->cbSecurityTrailer,
            pConnSizes->cbMaxSignature);
        break;
    case SECPKG_ATTR_APPLICATION_PROTOCOL:
        pApplicationProtocol = (PSecPkgContext_ApplicationProtocol)pvBuffer;
        printf("- SECPKG_ATTR_APPLICATION_PROTOCOL\n");

        memcpy(pcProtocolIdStr, pApplicationProtocol->ProtocolId, pApplicationProtocol->ProtocolIdSize);
        printf("\tSelected application protocol %s\n", pcProtocolIdStr);
        switch (pApplicationProtocol->ProtoNegoExt)
        {
        case SecApplicationProtocolNegotiationExt_None:
            printf("\tUsing: None\n");
            break;
        case SecApplicationProtocolNegotiationExt_NPN:
            printf("\tUsing: NPN\n");
            break;
        case SecApplicationProtocolNegotiationExt_ALPN:
            printf("\tUsing: ALPN\n");
            break;
        default:
            printf("\tUsing: UNRECOGNIZED\n");
            break;
        }
        switch (pApplicationProtocol->ProtoNegoStatus)
        {
        case SecApplicationProtocolNegotiationStatus_None:
            printf("\tStatus: NONE\n");
            break;
        case SecApplicationProtocolNegotiationStatus_Success:
            printf("\tStatus: SUCCESS\n");
            break;
        case SecApplicationProtocolNegotiationStatus_SelectedClientOnly:
            printf("\tStatus: CLIENTONLY\n");
            break;
        default:
            printf("\tStatus: UNRECOGNIZED\n");
            break;
        }
        break;
    case SECPKG_ATTR_ISSUER_LIST_EX:
        pIssrListEx = (PSecPkgContext_IssuerListInfoEx)pvBuffer;
        printf("- SECPKG_ATTR_ISSUER_LIST_EX:\n");

        DisplayIssuerListEx(pIssrListEx);
        if (pIssrListEx->cIssuers)
        {
            FreeContextBuffer(pIssrListEx->aIssuers);
        }
        break;

    case SECPKG_ATTR_REMOTE_CERT_CONTEXT:
        printf("- SECPKG_ATTR_REMOTE_CERT_CONTEXT:\n");
        DisplayCertChain(pRemoteCert, FALSE);
        break;

    case SECPKG_ATTR_LOCAL_CERT_CONTEXT:
        printf("- SECPKG_ATTR_LOCAL_CERT_CONTEXT:\n");
        DisplayCertChain(pLocalCert, TRUE);
        break;

    case SECPKG_ATTR_SESSION_INFO:
        pSessInfo = (PSecPkgContext_SessionInfo)pvBuffer;
        printf("- SECPKG_ATTR_SESSION_INFO:\n");
        if (SSL_SESSION_RECONNECT & pSessInfo->dwFlags)
        {
            printf("- Reconnect handshake.\n");
        }
        else
        {
            printf(": Full handshake.\n");
        }
        printf("- Session Flags    : 0x%x\n", pSessInfo->dwFlags);
        printf("- Session ID Length: %d\n", pSessInfo->cbSessionId);
        if (pSessInfo->rgbSessionId)
        {
            //FreeContextBuffer(pSessInfo->rgbSessionId);
        }
        break;

    case SECPKG_ATTR_KEY_INFO:
        dwMemSize = sizeof(SecPkgContext_KeyInfo);
        break;
    case SECPKG_ATTR_PROTO_INFO:
        dwMemSize = sizeof(SecPkgContext_ProtoInfo);
        break;
    case SECPKG_ATTR_EAP_KEY_BLOCK:
        dwMemSize = sizeof(SecPkgContext_EapKeyBlock);
        break;

    case SECPKG_ATTR_REMOTE_CERTIFICATES:
        pRemoteKCerts = (PSecPkgContext_Certificates)pvBuffer;
        break;

    case SECPKG_ATTR_LOCAL_CERT_INFO:
        pLclCertInfo = (PSecPkgContext_CertInfo)pvBuffer;
        break;

    case SECPKG_ATTR_SESSION_KEY:
        dwMemSize = sizeof(SecPkgContext_SessionKey);
        break;
    case SECPKG_ATTR_CC_POLICY_RESULT:
        dwMemSize = sizeof(SecPkgContext_ClientCertPolicyResult);
        break;

    default:
        printf("- Attribute not supported.\n");
        break;
    }

cleanup:

    if (pRemoteCert)
    {
        CertFreeCertificateContext(pRemoteCert);
        pRemoteCert = NULL;
    }
    if (pLocalCert)
    {
        CertFreeCertificateContext(pLocalCert);
        pLocalCert = NULL;
    }
    if (pvBuffer && 0 != dwMemSize)
    {
        DbglibLocalFree(pvBuffer);
        pvBuffer = NULL;
    }

    return dwStatus;
}

void
DisplayConnectionInfo(
    IN     PSecPkgContext_ConnectionInfo pConnectionInfo)
{
    char szString[MAX_INFO_BUFFER];

    RtlZeroMemory(szString, MAX_INFO_BUFFER);

    // print protocol
    switch (pConnectionInfo->dwProtocol)
    {
    case SP_PROT_TLS1_2_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "TLS 1.2");
        break;

    case SP_PROT_TLS1_1_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "TLS 1.1");
        break;

    case SP_PROT_TLS1_0_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "TLS 1.0");
        break;

    case SP_PROT_SSL3_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SSL 3.0");
        break;

    case SP_PROT_PCT1_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "PCT");
        break;

    case SP_PROT_SSL2_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SSL 2.0");
        break;

    case SP_PROT_TLS1_3_CLIENT:
        StringCchCopy(szString, MAX_INFO_BUFFER, "TLS 1.3");
        break;

    default:
        StringCchCopy(szString, MAX_INFO_BUFFER, "Unknown Protocol");
        printf("- Unknown Protocol: 0x%x\n", pConnectionInfo->dwProtocol);
        break;
    }
    printf("  Protocol\t\t: %s\n", szString);

    // print algo
    switch (pConnectionInfo->aiCipher)
    {
    case CALG_RC4:
        StringCchCopy(szString, MAX_INFO_BUFFER, "RC4");
        break;

    case CALG_3DES:
        StringCchCopy(szString, MAX_INFO_BUFFER, "Triple DES");
        break;

    case CALG_DES:
        StringCchCopy(szString, MAX_INFO_BUFFER, "DES");
        break;

    case CALG_RC2:
        StringCchCopy(szString, MAX_INFO_BUFFER, "RC2");
        break;

        // only Longhorn onwards
    case CALG_AES_128:
        StringCchCopy(szString, MAX_INFO_BUFFER, "AES-128");
        break;

        // only Longhorn onwards
    case CALG_AES_256:
        StringCchCopy(szString, MAX_INFO_BUFFER, "AES-256");
        break;

    default:
        StringCchCopy(szString, MAX_INFO_BUFFER, "Unknown Cipher");
        printf("- Unknown Cipher: 0x%x\n", pConnectionInfo->aiCipher);
        break;
    }
    printf("  Cipher\t\t: %s\n", szString);
    printf("  Cipher strength\t: %d\n", pConnectionInfo->dwCipherStrength);

    // print hash algo
    switch (pConnectionInfo->aiHash)
    {
    case CALG_MD5:
        StringCchCopy(szString, MAX_INFO_BUFFER, "MD5");
        break;

    case CALG_SHA1:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SHA 1");
        break;

    case CALG_SHA_256:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SHA 256");
        break;

    case CALG_SHA_384:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SHA 384");
        break;

    case CALG_SHA_512:
        StringCchCopy(szString, MAX_INFO_BUFFER, "SHA 512");
        break;

    default:
        StringCchCopy(szString, MAX_INFO_BUFFER, "Unknown Hash");
        printf("- Unknown Hash: 0x%x\n", pConnectionInfo->aiHash);
        break;
    }

    printf("  Hash\t\t: %s\n", szString);
    printf("  Hash strength\t: %d\n", pConnectionInfo->dwHashStrength);

    // print key exchange algo
    switch (pConnectionInfo->aiExch)
    {
    case CALG_RSA_KEYX:
    case CALG_RSA_SIGN:
        StringCchCopy(szString, MAX_INFO_BUFFER, "RSA");
        break;
    case CALG_KEA_KEYX:
        StringCchCopy(szString, MAX_INFO_BUFFER, "KEA");
        break;
    case CALG_DH_EPHEM:
        StringCchCopy(szString, MAX_INFO_BUFFER, "DH Ephemeral");
        break;
    case CALG_ECDH:
        StringCchCopy(szString, MAX_INFO_BUFFER, "ECDH Ephemeral");
        break;
    case CALG_ECDSA:
        StringCchCopy(szString, MAX_INFO_BUFFER, "ECDSA");
        break;

    default:
        StringCchCopy(szString, MAX_INFO_BUFFER, "Unknown Exchange Key");
        printf("- Unknown Exchange Key: 0x%x\n", pConnectionInfo->aiExch);
        break;
    }

    printf("  Key Exchange\t: %s\n", szString);
    printf("  Key Exchng strength : %d\n", pConnectionInfo->dwExchStrength);


} // DisplayConnectionInfo()
void

DisplayIssuerListEx(
    IN     PSecPkgContext_IssuerListInfoEx pIssuerListExInfo)
{
    char* pszIssuer = NULL;
    DWORD  dwCnt = 0;
    DWORD  i;

    // print the issuer list info
    printf("- Number of trusted certificate issuers: %d\n", pIssuerListExInfo->cIssuers);
    for (i = 0; i < pIssuerListExInfo->cIssuers; i++)
    {
        dwCnt = CertNameToStrA(X509_ASN_ENCODING,
            &pIssuerListExInfo->aIssuers[i],
            CERT_X500_NAME_STR,
            pszIssuer,
            dwCnt);

        if (0 == dwCnt)
        {
            printf("- CertNameToStrA(1) to get size FAILED!\n");
            goto cleanup;
        }
        else
        {
            pszIssuer = (char*)malloc(dwCnt);
            if (NULL == pszIssuer)
            {
                printf("- pszIssuer memory allocation FAILED!\n");
                goto cleanup;
            }
        }

        dwCnt = CertNameToStrA(X509_ASN_ENCODING,
            &pIssuerListExInfo->aIssuers[i],
            CERT_X500_NAME_STR,
            pszIssuer,
            dwCnt);
        if (0 == dwCnt)
        {
            printf("- CertNameToStrA(2) to get size FAILED!\n");
            goto cleanup;
        }
        else
        {
            printf("-  Issuer: %s\n", pszIssuer);
        }
        if (pszIssuer)
        {
            free(pszIssuer);
            pszIssuer = NULL;
            dwCnt = 0;
        }
    }

cleanup:

    return;

} // DisplayIssuerListEx()

/**********************************************************************
 Displays info from the server/client certificate
**********************************************************************/
void
DisplayCertChain(
    IN     PCCERT_CONTEXT  pCert,
    IN     BOOL            fLocal)
{
    CHAR            szName[1000];
    DWORD           dwVerificationFlags = 0;
    PCCERT_CONTEXT  pCurrentCert = NULL;
    PCCERT_CONTEXT  pIssuerCert = NULL;
    PCCERT_CHAIN_CONTEXT pChainTemp = NULL;

    // display leaf name
    if (!CertNameToStr(pCert->dwCertEncodingType,
        &pCert->pCertInfo->Subject,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName))
        )
    {
        printf("- Error 0x%x building subject name!\n", GetLastError());
    }

    printf("-");
    if (fLocal)
    {
        printf("  Client subject: %s\n", szName);
    }
    else
    {
        printf("  Server subject: %s\n", szName);
    }

    // display issue name
    if (!CertNameToStr(pCert->dwCertEncodingType,
        &pCert->pCertInfo->Issuer,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName))
        )
    {
        printf("- Error 0x%x building issuer name!\n", GetLastError());
    }

    if (fLocal)
    {
        printf("  Client issuer : %s\n", szName);
    }
    else
    {
        printf("  Server issuer : %s\n", szName);
    }

    //
    // Check that the remote server sent us the whole chain
    // Do a chainbuild and look at CAPI2 Logs.
    //

    if (!CertGetCertificateChain(NULL,
        pCert,
        NULL,
        pCert->hCertStore,
        NULL,
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
        NULL,
        &pChainTemp)
        )
    {
        if (NULL == pChainTemp)
        {
            printf("  CertGetCertificateChain failed with : %d\n", GetLastError());
        }
    }

    if (pChainTemp)
    {
        CertFreeCertificateChain(pChainTemp);
        pChainTemp = NULL;
    }

    // display certificate chain
    pCurrentCert = pCert;
    while (pCurrentCert != NULL)
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(
            pCurrentCert->hCertStore,
            pCurrentCert,
            pIssuerCert,
            &dwVerificationFlags);

        if (pIssuerCert == NULL)
        {
            if (pCurrentCert != pCert)
            {
                //CertFreeCertificateContext(pCurrentCert);
                pCurrentCert = NULL;
            }
            break;
        }

        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
            &pIssuerCert->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof(szName))
            )
        {
            printf("- Error 0x%x building CA subject name!\n", GetLastError());
        }
        printf("  CA subject: %s\n", szName);

        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
            &pIssuerCert->pCertInfo->Issuer,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof(szName))
            )
        {
            printf("- Error 0x%x building CA issuer name!\n", GetLastError());
        }
        printf("  CA issuer: %s\n", szName);

        if (pCurrentCert != pCert)
        {
            //CertFreeCertificateContext(pCurrentCert);
            pCurrentCert = NULL;
        }

        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }

} // DisplayCertChain()

//++----------------------------------------------------------------------
//  NAME:  WebcliQueryContext
//  
//  DESC:  calls the required QueryContextAttributes calls
//  
//  ARGUMENTS: 
//  - PCtxtHandle : context handle
//
//  RETURNS:   
//  - DWORD: status code
//  
//  NOTE:      
//--------------------------------------------------------------------++//
DWORD
WebcliQueryContext(
    IN     PCtxtHandle phContext)
{
    DWORD  dwStatus = MYDBG_SUCCESS;
    DWORD  dwAttr = 0;

    // SECPKG_ATTR_EAP_KEY_BLOCK
    if (g_fQryCtxtEapKeyBlock)
    {
        dwAttr = SECPKG_ATTR_EAP_KEY_BLOCK;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

cleanup:

    return dwStatus;
} // WebcliQueryContext

/**********************************************************************
Drains the connection of remaining data.
If fGracefulDrain is specified, it tries to process the data received through schannel and
returns any errors produced while reading or decrypting, or handling post handshake messages
to the caller.
Otherwise, it will simply read and discard data from the socket until it does not see anymore
or a socket error is produced.
pbIoBuffer is used as scratch space and the data placed in pbIoBuffer is not meant to be consumed.
Remarks:
It is not safe to call this function more than once for a !fUseSockets run.
fUseSockets sends and receives a zero-length buffer to emulate recv returning 0.
Unlike recv, calling it more than once results in consuming data intended for the next connection.
**********************************************************************/
unsigned long
DrainConnection(
    _In_ SOCKET Socket,
    _In_ CtxtHandle* phContext,
    _In_ CredHandle* phClientCreds,
    _Inout_updates_bytes_(cbIoBuffer) PBYTE pbIoBuffer,
    _In_ DWORD cbIoBuffer,
    _In_ PQUIC_KEYS pQuicApplicationKeys,
    _In_ BOOL fGracefulDrain,
    _Out_ PBOOL pfReceivedCloseNotify)
{
    if (Socket == INVALID_SOCKET ||
        pbIoBuffer == NULL ||
        cbIoBuffer == 0 ||
        fGracefulDrain && (phContext == NULL || phClientCreds == NULL || pfReceivedCloseNotify == NULL))
    {
        return STATUS_INVALID_PARAMETER;
    }

    DWORD dwStatus = STATUS_SUCCESS;
    SecBuffer ExtraData = { 0 };
    DWORD cbData = 0;
    while (TRUE)
    {
        if (cbData == 0 || dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            cbData = recv(Socket, (LPSTR)pbIoBuffer, cbIoBuffer, 0);
        }

        if (cbData == 0)
        {
            // No more data, we are done.
            break;
        }

        if (SOCKET_ERROR == cbData)
        {
            printf("- Socket recv failed with %d!\n", WSAGetLastError());
            return MYDBG_ERROR_ERROR;
        }

        printf("[Client] Drained %d bytes from connection:\n", cbData);
        PrintHexDump(cbData, pbIoBuffer);

        if (fGracefulDrain)
        {
            PBYTE pbExtra = NULL;
            DWORD cbExtra = 0;
            dwStatus = SslReadPacket(
                Socket,
                phContext,
                pbIoBuffer,
                cbIoBuffer,
                &cbData,
                &pbExtra,
                &cbExtra,
                pQuicApplicationKeys,
                NULL);

            if (dwStatus != SEC_E_OK &&
                dwStatus != SEC_I_CONTEXT_EXPIRED &&
                dwStatus != SEC_I_RENEGOTIATE)
            {
                printf("- SslReadPacket failed with 0x%lx\n", dwStatus);
                return dwStatus;
            }
            printf("- Drained %d bytes from the half-open connection.\n", cbData);
            if (dwStatus == SEC_I_CONTEXT_EXPIRED)
            {
                // Got close_notify, we are done.
                *pfReceivedCloseNotify = TRUE;
                break;
            }
            else if (dwStatus == SEC_I_RENEGOTIATE)
            {
                SecBuffer ExtraData = { cbData, SECBUFFER_EXTRA, pbIoBuffer };
                cbData = 0;
                dwStatus = ClientHandshakeLoop(
                    Socket,
                    phClientCreds,
                    phContext,
                    FALSE,
                    &ExtraData,
                    NULL,
                    pQuicApplicationKeys);

                if (dwStatus != SEC_E_OK)
                {
                    printf("- ClientHandshakeLoop while draining connection failed with error 0x%x!!\n", dwStatus);
                    return dwStatus;
                }
                if (ExtraData.pvBuffer)
                {
                    if (ExtraData.cbBuffer > cbIoBuffer)
                    {
                        return STATUS_INTERNAL_ERROR;
                    }
                    MoveMemory(pbIoBuffer, ExtraData.pvBuffer, ExtraData.cbBuffer);
                    cbData = ExtraData.cbBuffer;
                }
            }
            else if (pbExtra != NULL) // implicit and: SslReadPacket returns SEC_E_OK
            {
                MoveMemory(pbIoBuffer, pbExtra, cbExtra);
                cbData = cbExtra;
            }
            else // implicit: SslReadPacket returns SEC_E_OK
            {
                // No extra, so reset for the next loop so we attempt another read.
                cbData = 0;
            }
        }
        else
        {
            // Discard the data.
            cbData = 0;
        }
    }

    return STATUS_SUCCESS;
}

//++----------------------------------------------------------------------
//  NAME:  DbglibLocalFree
//
//  DESC:  Free memory
//
//  ARGUMENTS:
//  - PBYTE: pointer to the buffer to be freed
//
//  RETURNS:   nothing
//
//  NOTE:
//--------------------------------------------------------------------++//

void
PrintHexDump(
    IN DWORD cbLength,
    IN PBYTE pbBuffer)
{
#define BYTES_PER_LINE  16

    DWORD i = 0, count = 0, index = 0;
    CHAR  rgbDigits[] = "0123456789abcdef";
    CHAR  rgbLine[100];                    // 100 is big enough for one line
    DWORD dwCursor = 0;

    for (index = 0; cbLength;
        cbLength -= count, pbBuffer += count, index += count)
    {
        count = (cbLength > BYTES_PER_LINE) ? BYTES_PER_LINE : cbLength;

        StringCchPrintf(rgbLine, 1, "%4.4x  ", index);
        dwCursor = strlen(rgbLine);

        for (i = 0; i < count; i++)
        {
            rgbLine[dwCursor++] = rgbDigits[pbBuffer[i] >> 4];
            rgbLine[dwCursor++] = rgbDigits[pbBuffer[i] & 0x0f];
            if (i == (BYTES_PER_LINE / 2 - 1))
                rgbLine[dwCursor++] = ':';
            else
                rgbLine[dwCursor++] = ' ';
        }

        for (; i < BYTES_PER_LINE; i++)
        {
            rgbLine[dwCursor++] = ' ';
            rgbLine[dwCursor++] = ' ';
            rgbLine[dwCursor++] = ' ';
        }

        rgbLine[dwCursor++] = ' ';

        for (i = 0; i < count; i++)
        {
            if (pbBuffer[i] < 32 || pbBuffer[i] > 126)
                // this is a non-printable character
                rgbLine[dwCursor++] = '.';
            else
                rgbLine[dwCursor++] = pbBuffer[i];
        }

        rgbLine[dwCursor++] = 0;
        printf("%s\n", rgbLine);
    }
} // PrintHexDump

DWORD
AllocateOutputBuffer(
    _In_ PSecBuffer pOutBuffer,
    _In_ BOOLEAN fUserAllocate,
    _In_ BOOLEAN fAllocateSmall,
    _In_opt_ DWORD dwSize)
{
    if (pOutBuffer == NULL)
    {
        return (DWORD)SEC_E_INVALID_PARAMETER;
    }

    FreeOutputBuffer(pOutBuffer);

    if (!fUserAllocate && !fAllocateSmall)
    {
        pOutBuffer->cbBuffer = 0;
        return ERROR_SUCCESS;
    }

    // If we are allocating our own memory this will be the size returned by Schannel.
    DWORD requiredSize = ((fAllocateSmall && pOutBuffer->cbBuffer > 1) ||
        (fUserAllocate && pOutBuffer->cbBuffer > dwSize))
        ? pOutBuffer->cbBuffer : 0;

    pOutBuffer->cbBuffer = 0;

    if (requiredSize > 0)
    {
        pOutBuffer->cbBuffer = requiredSize;
    }
    else if (fAllocateSmall)
    {
        pOutBuffer->cbBuffer = 1;
    }
    else if (dwSize > 0)
    {
        pOutBuffer->cbBuffer = dwSize;
    }

    pOutBuffer->pvBuffer = LocalAlloc(LPTR, pOutBuffer->cbBuffer);
    if (pOutBuffer->pvBuffer == NULL)
    {
        printf("- Error 0x%x returned by LocalAlloc\n", ERROR_NOT_ENOUGH_MEMORY);
        return  ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

VOID
FreeOutputBuffer(
    _In_ PSecBuffer pOutBuffer)
{

    if (pOutBuffer == NULL)
    {
        return;
    }

    pOutBuffer->pvBuffer = NULL;

    // This function does not zero cbBuffer by-design as the value is needed when testing -allocSmall, where cbBuffer would contain the
    // required size of the buffer after the first ISC/ASC and zeroing it out would cause AllocateOutputBuffer to keep allocating
    // 1-byte buffers, resulting in an infinite loop.
}

//++----------------------------------------------------------------------
//  NAME:  DbglibLocalAlloc
//
//  DESC:  Allocate memory
//
//  ARGUMENTS:
//  - DWORD size: size of memory allocation
//
//  RETURNS:
//  - PVOID: pointer to allocated buffer
//
//  NOTE:  free allocated buffer via KrnlDigLocalFree
//--------------------------------------------------------------------++//
PVOID
DbglibLocalAlloc(
    IN ULONG ulBufferSize
)
{
    PVOID  pBuffer = NULL;

    pBuffer = (PVOID)LocalAlloc(LMEM_ZEROINIT, ulBufferSize);

    if (NULL == pBuffer)
    {
        printf("- Memory Allocation failed!\n");
        return NULL;
    }

    return pBuffer;
}

VOID
DbglibLocalFree(
    IN PVOID pBuffer
)
{
    LocalFree(pBuffer);
    pBuffer = NULL;
}
