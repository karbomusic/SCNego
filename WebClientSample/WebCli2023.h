#pragma once

// error and success codes definition
#define WEBCLI_ERROR_SUCCESS     0
#define WEBCLI_ERROR_ERROR       -1

#define STATUS_SUCCESS 0
#define STATUS_INTERNAL_ERROR            ((NTSTATUS)0xC00000E5L)

#define HTTPSPROV_ACTION                                        \
            { 0x573e31f8,                                       \
              0xaaba,                                           \
              0x11d0,                                           \
              { 0x8c, 0xcb, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } \
            }

#ifndef NTSTATUS
#define NTSTATUS long
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define IO_BUFFER_SIZE  1000*1000

// webcli query and check options
#define SECPKG_ATTR_CIPHER_INFO_CIPHERSUITE   0x01
#define SECPKG_ATTR_CIPHER_INFO_KEYTYPE   0x02
#define SECPKG_ATTR_SESSION_INFO_FLAG 0x03
#define SECPKG_ATTR_SESSION_INFO_MACHINEID 0x04

void DisplayCertChain(
    IN     PCCERT_CONTEXT  pServerCert,
    IN     BOOL            fLocal);

void
DisplayConnectionInfo(
    IN     PSecPkgContext_ConnectionInfo   pConnectionInfo);

void
DisplayConnectionInfoEx(
    IN     PSecPkgContext_ConnectionInfoEx pConnectionInfoEx);

void
DisplayNegotiatedExtensions(
    __in PSecPkgContext_NegotiatedTlsExtensions pNegotiatedExtensions);

DWORD
SetContextWrapper(
    IN     DWORD       dwAttr,
    IN     PCtxtHandle phContext
);

///////////////////////////////////////////////////////////////////////////////////////////////////
// Explicit Session State Management
///////////////////////////////////////////////////////////////////////////////////////////////////

DWORD
DisconnectFromServer(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     CtxtHandle* phContext,
    IN     PQUIC_KEYS   pQuicApplicationKeys);

DWORD
DrainConnection(
    _In_ SOCKET Socket,
    _In_ CtxtHandle* phContext,
    _In_ CredHandle* phClientCreds,
    _Inout_updates_bytes_(cbIoBuffer) PBYTE pbIoBuffer,
    _In_ DWORD cbIoBuffer,
    _In_ PQUIC_KEYS pQuicApplicationKeys,
    _In_ BOOL fGracefulDrain,
    _Out_ PBOOL pfReceivedCloseNotify);

DWORD
HttpsGetFile(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     CtxtHandle* phContext,
    IN     LPSTR        pszFileName,
    IN     PQUIC_KEYS   pQuicApplicationKeys,
    IN     SecBuffer* pExtraData);

DWORD
InitiateRenegotiation(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     LPSTR        pszServerName,
    IN     CtxtHandle* phContext);

DWORD
InitPackage(DWORD* pcbMaxMessage);

DWORD
ManualServerCertValidation(
    IN     PSTR        pszTargetName,
    IN     DWORD       dwCertFlags,
    IN     SOCKET      Socket,
    IN     PCredHandle phCreds,
    IN     PCtxtHandle phContext);

DWORD
PerformClientHandshake(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     LPSTR        pszServerName,
    IN     CtxtHandle* phContext,
    OUT     SecBuffer* pExtraData,
    IN     PQUIC_KEYS   pQuicApplicationKeys);

DWORD WebClient();

DWORD
ClientHandshakeLoop(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     CtxtHandle* phContext,
    IN     BOOL         fDoInitialRead,
    IN OUT SecBuffer* pExtraData,
    IN     PQUIC_KEYS   pQuicHandshakeKeys,
    IN     PQUIC_KEYS   pQuicApplicationKeys);

DWORD
BuildAndSendAlert(
    IN     SOCKET       Socket,
    IN     PCredHandle  phCreds,
    IN     CtxtHandle* phContext,
    IN     DWORD        ErrorReturned);

DWORD
CreateClientCredentials(
    __in_opt LPSTR pszUserName,
    __in_opt LPSTR pszPfxPath,
    __inout PCredHandle phCreds);

DWORD
DisableReconnects(
    IN     PCtxtHandle hContext);

void
PrintSecPkgsInfo(CtxtHandle* phContext);

DWORD
ProgrammaticClientCredentials(
    IN     CredHandle* phCreds,
    IN     CtxtHandle* phContext);

DWORD
QueryContextBufferSizes(CtxtHandle* phContext);

unsigned long
QueryContextWrapper(
    IN     DWORD       dwAttr,
    IN     PCtxtHandle phContext);

BOOLEAN
ReceivedExpectedGenericExtension(
    _In_ PSecBuffer pReceivedExtensions);

DWORD
SetEarlyStart(
    IN     PCtxtHandle phContext);

DWORD
SslReadPacket(
    IN     SOCKET      Socket,
    IN     CtxtHandle* phContext,
    OUT PBYTE       pbBuffer,
    IN     DWORD       cbBuffer,
    OUT DWORD* pcbDataRead,
    OUT PBYTE* ppbExtra,
    OUT DWORD* pcbExtra,
    IN     PQUIC_KEYS  pQuicApplicationKeys,
    OUT    PBOOL       pfRecievedEmptyMessage);

DWORD
VerifyServerCertificate(
    IN     PCCERT_CONTEXT  pServerCert,
    IN     PSTR            pszServerName,
    IN     DWORD           dwCertFlags);

DWORD
VerifyServerCertificateWVT(
    IN     PCCERT_CONTEXT  pServerCert,
    IN     PSTR            pszServerName,
    IN     DWORD           dwCertFlags);

DWORD
GetTlsAlgorithmForCryptID(
    IN     LPSTR pszOId);

DWORD
VerifyServerCertSubjectName(
    IN     PCtxtHandle phContext);

DWORD
WebcliQueryContext(
    IN     PCtxtHandle phContext);

void Usage(void);
unsigned long
CreateDefaultClientCredentials(
    IN OUT PCredHandle phClientCreds);
INT
ConnectToServer(
    IN     LPSTR    pszServerName,
    IN     INT      iPortNumber,
    OUT SOCKET* pSocket);
DWORD
WebcliSetContext(
    IN     PCtxtHandle phContext);
unsigned long
HttpsSendRequest(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN     CtxtHandle* phContext,
    IN     LPSTR           pszFileName,
    IN     PQUIC_KEYS      pQuicApplicationKeys);
void
DisplayIssuerListEx(
    IN     PSecPkgContext_IssuerListInfoEx pIssuerListExInfo);
void
PrintHexDump(
    IN DWORD cbLength,
    IN PBYTE pbBuffer);

DWORD
AllocateOutputBuffer(
    _In_ PSecBuffer pOutBuffer,
    _In_ BOOLEAN fUserAllocate,
    _In_ BOOLEAN fAllocateSmall,
    _In_opt_ DWORD dwSize);

VOID
FreeOutputBuffer(
    _In_ PSecBuffer pOutBuffer);

