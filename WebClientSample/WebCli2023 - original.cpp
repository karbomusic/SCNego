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

#define _CRT_SECURE_NO_WARNINGS
#define MAX_SUPPORTED_ALGORITHMS    10

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <wincred.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")


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

//
// GLOBALS
//

// User options.
LPSTR   g_pszServerName     = (LPSTR)"";
LPSTR   g_pszTargetName     = NULL;
LPSTR   g_pszUserName       = NULL;
LPSTR   g_pszPfxPath        = NULL;
INT     iPortNumber         = 443;
DWORD   g_IoBufSize         = IO_BUFFER_SIZE;
LPSTR   pszFileName         = (LPSTR)"default.htm";
LONG    g_dwIterationCount  = 1;
BOOL    fUseProxy           = FALSE;
BOOL    g_fSaveReceivedFile = FALSE;
LPSTR   pszReceivedFileName = (LPSTR)"received.bin";
BOOL    g_fSocketStarted    = FALSE;

DWORD   g_dwProtocol                  = 0;
DWORD   g_dwNegotiatedProtocol        = 0;
DWORD   g_dwDisabledProtocols         = 0;
BOOL    g_fUseSchCredentials          = FALSE;
BOOL    g_fAllowNullEncryptionCiphers = FALSE;
DWORD   g_dwMinCipherStrength         = 0;
DWORD   g_dwMaxCipherStrength         = 0;
DWORD   g_cSupportedAlgs              = 0;
ALG_ID  g_rgbSupportedAlgs[MAX_SUPPORTED_ALGORITHMS] = { 0 };
BOOL    g_fUseSmallBuffer             = FALSE;  // intentionally allocate a small buffer to get SEC_E_BUFFER_TOO_SMALL and realloc
BOOL    g_fNonContiguousBuffers       = FALSE;
BOOLEAN g_fNoRecordLayer              = FALSE;
LPSTR   g_pszServerSpeaksFirst        = NULL;

// Generic extensions.
DWORD   g_dwGeExtensionType       = ULONG_MAX;
DWORD   g_dwGeHandshakeType       = ULONG_MAX;
LPSTR   g_pszGeContents           = NULL;
DWORD   g_dwGeExtensionTypeVerify = ULONG_MAX;
DWORD   g_dwGeHandshakeTypeVerify = ULONG_MAX;
LPSTR   g_pszGeContentsVerify     = NULL;

BOOL    g_fUseSecureCiphers = FALSE;

// server revocation option
DWORD   dwSrvCertRvcnOpt = 0;

LPSTR   g_pszSrvCertNameToVerify = NULL;

#define CLIENT_AUTH_MANUAL          0  // user specifies client cert to pick
#define CLIENT_AUTH_PROGRAMMATIC    1  // webcli picks up cert programmatically
#define CLIENT_AUTH_AUTOMATIC       3  // schannel picks up cert automatically
#define CLIENT_AUTH_PICKLED_CRED    4  // using SEC_WINNT_AUTH_IDENTITY_EX
#define CLIENT_AUTH_MEMORY_STORE    5  // use memory store
#define CLIENT_AUTH_CALL_CAQ        6  // call CryptAcquireContext

#define CLIENT_AUTH_DEFAULT_MODE    CLIENT_AUTH_PROGRAMMATIC
#define CLIENT_AUTH_NO_CERT         7  // don't send a client certificate

// the client certificate selection method
DWORD   dwClientAuthMode = CLIENT_AUTH_DEFAULT_MODE;

BOOL    g_fPrecheckSrvCert = FALSE;

// the below flag specifies ISC_REQ_MUTUAL_AUTH,
// whereby Schannel automatically validates the server cert.
BOOL    g_fMutualAuth = FALSE;
BOOL    g_fManualCredValidation = FALSE;

BOOL    g_fSendAlert = FALSE;  // send alert
BOOL    g_fKeepAlive = FALSE;  // keep connection alive
BOOL    g_fReconnect = FALSE;  // reconnection scenario
BOOL    g_fRenegotiate = FALSE;  // renegotiation scenario
BOOL    g_fSendCloseNotify = FALSE;  // send close_notify
BOOL    g_fUseNewQOP = FALSE;  // generate alerts via EncryptMessage
BOOL    g_fConnectionMode = FALSE;  // Stream or Connection Mode
BOOL    g_fCheckOcsp = FALSE; //do we check for OCSP stapling?
BOOL    g_fDisableReconnects = FALSE;  // Disable reconnects
BOOL    g_fPackageInfo = FALSE;  // print EnumerateSecurityPackage
BOOL    g_fAllocateMemory = FALSE;  // SSPI app allocates it's own memory
BOOL    g_fSendExtraRecord = FALSE;  // Flag to check if schannel needs to fragment record in 1 and (n-1) bytes
BOOL    g_fVerifyExtraRecord = FALSE;  // Flag to check if the peer has sent extra record
BOOL    g_fExtraDataReceived = FALSE;              // Flag to check if extra data is received
BOOL    g_fMeasureAlertRespTime = FALSE; //Flag to check if we need to measure the response time of an ALERT
BOOL    g_fDowngrade = FALSE;            // Flag to check if we want to downgrade SSLv2 compatible hello to SSLv2 only
DWORD   g_dwMaxToken = 0;      // Maximum message size the package can handle
DWORD   g_dwSendRootCert = 0;      // Other Cred Flags (Send Root Cert)
BOOL    g_fIgnoreHttpError = FALSE;
BOOL    g_fIscReqDeferredCredValidation = FALSE; // Request ISC_REQ_DEFERRED_CRED_VALIDATION
BOOL    g_fAchReqDeferredCredValidation = FALSE; // Request SCH_CRED_DEFERRED_CRED_VALIDATION
BOOL    g_fNoPostHandshakeAuth = FALSE; // Don't send post_handshake_auth extension in TLS 1.3 Client Hello

//
// query context attributes
//
// both user and kernel mode
BOOL    g_fQryCtxtAll = FALSE;
BOOL    g_fQryCtxtConnInfo = FALSE;
BOOL    g_fQryCtxtSizes = FALSE;
BOOL    g_fQryCtxtCipherInfo = TRUE;  // QueryContextAttributes Cipher Info
BOOL    g_fQryCtxtSupportedSignatures = FALSE;
BOOL    g_fQryCtxtApplicationProtocol = FALSE;
BOOL    g_fQryCtxtKeyingMaterialInproc = FALSE;
BOOL    g_fQryCtxtCertValidationResult = FALSE;
BOOL    g_fQryCtxtCertValidationResultInProc = FALSE;
BOOL    g_fQryCtxtSerializedRemoteCertInProc = FALSE;

// If this is specified without webcli's manual server cert validation, then we simply query during
// the handshake and check that we get a valid cert. If specified with, this will also query the
// out-proc again after the handshake and use it in the manual server cert validation like
//  g_fQryCtxtSerializedRemoteCertInProc does.
BOOL    g_fQryCtxtSerializedRemoteCert = FALSE;

// only user mode
//QueryContextIssuerListExParams g_QryCtxtIssrListExParams = { 0 }; // Keeps track of vfTrustedIssuers* arguments
BOOL    g_fQryCtxtIssrListEx = FALSE;  // QueryContextAttributes issuer list
BOOL    g_fQryCtxtRemoteCert = FALSE;
BOOL    g_fQryCtxtLocalCert = FALSE;
BOOL    g_fQryCtxtSessInfo = FALSE;
BOOL    g_fQryCtxtKeyInfo = FALSE;  // QueryContextAttributes key
BOOL    g_fQryCtxtProtoInfo = FALSE;  // QueryContextAttributes protocol
BOOL    g_fQryCtxtEapKeyBlock = FALSE;  // QueryContextAttributes NULL;
BOOL    g_fQryCtxtAppData = FALSE;
BOOL    g_fQryCtxtLifeSpan = FALSE;
BOOL    g_fQryCtxtNames = FALSE;
BOOL    g_fQryCtxtAuthority = FALSE;
BOOL    g_fQryCtxtKeyingMaterial = FALSE; // SCA for EKMI not supported in KM

// query credentials attributes
BOOL    g_fQueryAllCreds = FALSE;
BOOL    g_fQuerySuppAlgs = FALSE;
BOOL    g_fQueryCiphStrgths = FALSE;
BOOL    g_fQuerySuppProtocols = FALSE;
BOOL    g_fQueryCredNames = FALSE;

// query and check values
BOOL    g_fQueryAndCheckReconnect = FALSE;
DWORD   g_dwReconnect = SSL_SESSION_RECONNECT;
BOOL    g_fQueryAndCheckCiphersuite = FALSE;
DWORD   g_dwCipherSuite = 0;
BOOL    g_fQueryAndCheckKeyType = FALSE;
DWORD   g_dwKeyType = 0;
BOOL    g_fQueryAndCheckMachineId = FALSE;
DWORD   g_dwMachineID = 0;

#define MAX_EAP_PRF 4

// set context attributes
BOOL    g_fSetCtxtAll = FALSE;
BOOL    g_fSetAppData = FALSE;
BOOL    g_fSetKeyingMaterialInfo = FALSE;
BOOL    g_fSetEAPProtocol = FALSE;
DWORD   g_dwSetEapPRF = 0;

// QueryContextAttribute called and sizes populated
SecPkgContext_Sizes        pvSizesConnection;
SecPkgContext_StreamSizes  pvSizesStream;

BOOL    g_ftestEmptyMessage = FALSE;
BOOL    g_fWaitForDriverStart = FALSE;  // server and client will both use ssptestdd, so wait for server to start the service

BOOL    g_fReconnectToSecondServer = FALSE;
LPSTR   g_pszSecondServerName = (LPSTR)"localhost";

LPSTR  g_pszTLSPackageName = (LPSTR)UNISP_NAME;

// Compat cli stuff
BOOL    g_fCompatCliMode = FALSE;
wchar_t g_pszNegotiatedCipherSuite[256] = L"";
char    g_pszNegotiatedProtocol[256] = "";
DWORD   g_dwNumServerSends = 0;

PVOID   ClientContext;

UNICODE_STRING  Package;
UNICODE_STRING  ServerName;

// wireless hack global
HCRYPTPROV      g_hProv = 0;
PCCERT_CONTEXT  g_pDupCertContext = NULL;

BOOL fUseSockets = TRUE;

BOOL    g_CheckFlagExtendedError = FALSE;

// Causes this client to send zero-length application data records to the server.
// This happens before, during and after app data payload and multiple ZLA records
// in a row.
BOOL    g_fSendZeroLengthApplicationData = FALSE;

// Allows this client to accept zero-length application data records from the server.
// If not set, we will not handle receipt of them.
BOOL    g_fAcceptZeroLengthApplicationData = FALSE;

BOOL    g_fVerifyReceiveCloseNotify = FALSE;

BOOL    g_fAllowEarlyDisconnect = FALSE;

// Causes client to attempt to encrypt data after receiving SEC_I_RENEGOTIATE from DecryptMessage.
// For example, NST in TLS 1.3. We should be able to continue calling EncryptMessage until we call ISC.
BOOL    g_fEncryptAfterPostHandshake = FALSE;

#define WINSOCK_VERSION_USED     0x0002

// Expected error code
DWORD   g_dwExpectedISCError = ERROR_SUCCESS;

// Early (false) start
BOOL    g_fEarlyStartRequested = FALSE;
BOOL    g_fSetTlsClientEarlyStart = FALSE;
BOOL    g_fEarlyStartReady = FALSE;
BOOL    g_fEarlyStartGetSent = FALSE;

DWORD WebClient();

// For QCA/SCA SECPKG_ATTR_KEYING_MATERIAL/SECPKG_ATTR_KEYING_MATERIAL_INFO
const DWORD KEYING_MATERIAL_LENGTH = 512;  // Arbitrary requested length of keying material.

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

/**********************************************************************
 Usage information
***********************************************************************/
void Usage(void)
{
    printf("\n");
    printf("USAGE: webcli -s<server> [ <options> ]\n");
    printf("\n");
    printf("  -s<server>      DNS name of server\n");
    printf("  -target:<name>  If target server name is differnt from DNS name\n");
    printf("  -p<port>        Port server is listening on (default 443)\n");
    printf("  -IoBufSize:<size> Size of the input/output buffer (between 1 and %d)\n", IO_BUFFER_SIZE);
    printf("  -f<file>        Name of file to retrieve (default \"%s\")\n", pszFileName);
    printf("  -o<file>        Output file received (default \"%s\")\n", pszReceivedFileName);
    printf("  -P<protocol>    Protocol to use\n");
    printf("                    0 = SP_PROT_ALL\n");
    printf("                    1 = PCT 1.0        3 = SSL 3.0\n");
    printf("                    2 = SSL 2.0        4 = TLS 1.0\n");
    printf("                    5 = TLS 1.1        6 = TLS 1.2\n");
    printf("                    7 = TLS 1.3\n");
    printf("  -D<protocol>    Protocol(s) to disable:\n");
    printf("                  (default is none)\n");
    printf("                    1 = PCT 1.0        3 = SSL 3.0\n");
    printf("                    2 = SSL 2.0        4 = TLS 1.0\n");
    printf("                    5 = TLS 1.1        6 = TLS 1.2\n");
    printf("                    7 = TLS 1.3\n");
    printf("  -E<alg>         Key exchange algorithm(s) to use\n");
    printf("                    1 = RSA            2 = DHE\n");
    printf("                    3 = ECDHE\n");
    printf("  -C<alg>         Symmetric algorithm(s) to use:\n");
    printf("                    1 = RC4            2 = RC2\n");
    printf("                    3 = DES            4 = Triple DES\n");
    printf("                    5 = AES-128        6 = AES - 256\n");
    printf("  -hash:<alg>     Hash algoritm(s) to use\n");
    printf("                    1 = SHA            2 = MD5\n");
    printf("                    3 = SHA256         4 = SHA384\n");
    printf("                    5 = SHA512\n");
    printf("  -n<size>        Minimum Cipher Strength\n");
    printf("  -N<size>        Maximum Cipher Strength\n");
    printf("  -stream         Stream mode convention (default)\n");
    printf("  -connection     Connection mode convention\n");
    printf("  -NoRecordLayer  Disables the TLS 1.3+ record layer\n");
    printf("  -vfServerSpeaksFirst: Expected server speaks first message contents\n");
    printf("                        (Only works in combination with -NoRecordLayer)\n");
    printf("  -qctxt:<attr>   Context attributes to query \n");
    printf("                   0  = Query All.\n");
    printf("                   1  = SECPKG_ATTR_CONNECTION_INFO\n");
    printf("                   2  = SECPKG_ATTR_STREAM_SIZES\\SIZES\n");
    printf("                   3  = SECPKG_ATTR_ISSUER_LIST_EX\n");
    printf("                   4  = SECPKG_ATTR_REMOTE_CERT_CONTEXT (user mode)\n");
    printf("                   5  = SECPKG_ATTR_LOCAL_CERT_CONTEXT (user mode)\n");
    printf("                   6  = SECPKG_ATTR_SESSION_INFO (user mode)\n");
    printf("                   7  = SECPKG_ATTR_KEY_INFO (user mode)\n");
    printf("                   8  = SECPKG_ATTR_PROTO_INFO (user mode)\n");
    printf("                   15 = SECPKG_ATTR_CIPHER_INFO \n");
    printf("                   16 = SECPKG_ATTR_APP_DATA \n");
    printf("                   17 = SECPKG_ATTR_LIFESPAN \n");
    printf("                   18 = SECPKG_ATTR_NAMES \n");
    printf("                   20 = SECPKG_ATTR_SUPPORTED_SIGNATURES \n");
    printf("                   21 = SECPKG_ATTR_APPLICATION_PROTOCOL \n");
    printf("                   23 = SECPKG_ATTR_AUTHORITY \n");
    printf("                   26 = SECPKG_ATTR_KEYING_MATERIAL_INPROC \n");
    printf("                   27 = SECPKG_ATTR_KEYING_MATERIAL, requires sctxt:2 \n");
    printf("                   28 = SECPKG_ATTR_CERT_CHECK_RESULT \n");
    printf("                   29 = SECPKG_ATTR_CERT_CHECK_RESULT_INPROC \n");
    printf("                   30 = SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT_INPROC \n");
    printf("                   31 = SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT \n");
    printf("  -qcred:<attr>   Credentials attributes to query \n");
    printf("                    0 = Query All.\n");
    printf("                    1 = SECPKG_ATTR_SUPPORTED_ALGS\n");
    printf("                    2 = SECPKG_ATTR_CIPHER_STRENGTHS\n");
    printf("                    3 = SECPKG_ATTR_SUPPORTED_PROTOCOLS\n");
    printf("                    4 = SECPKG_CRED_ATTR_NAMES\n");
    printf("  -sctxt:<attr>     Set context attributes\n");
    printf("                    0 = Set All.\n");
    printf("                    1 = SECPKG_ATTR_APP_DATA\n");
    printf("                    2 = SECPKG_ATTR_KEYING_MATERIAL_INFO\n");
    printf("  -sEap:<EAP_PRF>     Set context Eap PRF\n");
    printf("                    0 = EAP_PRF_EAPTLS_MPPE \n");
    printf("                    1 = EAP_PRF_TTLSV0_MPPE\n");
    printf("                    2 = EAP_PRF_TTLSV0_CHALLENGE\n");
    printf("                    3 = EAP_PRF_FAST_MPPE\n");
    printf("                    %d = Set and Query All.\n", MAX_EAP_PRF);
    printf("  -qchkmid:<attr>  Check the SessionID for MachineID \n");
    printf("                    Enter MachineID in Hex [4 Bytes]\n");
    printf("  -qchkcs:<attr>  Check the ciphersuite negotiated \n");
    printf("                    Enter ciphersuite number in Hex\n");
    printf("  -qchkkey:<attr> Check the key info negotiated \n");
    printf("                    23 = ECC curve p256\n");
    printf("                    24 = ECC curve p384\n");
    printf("                    25 = ECC curve p521\n");
    printf("\n");
    printf("Server Certificate validation options:\n");
    printf("  -autoSrvChk     Schannel performs server cert validation.\n"
        "                  (Default: Manually validate server cert)\n");
    printf("  -noSrvNameChk   Schannel doesn't compare supplied target name with subject.\n");
    printf("                  (only valid with -autoSrvChk)\n");
    printf("  -verifySrvSubjectName:<name> Verify that the server certificate subject name matches the provided value.\n");
    printf("  -noSrvCertChk   No server cert validation performed.\n"
        "                  (only valid with manual validation)\n");
    printf("  -wvt            Use WinVerifyTrust to validate the server certificate.\n");
    printf("  -alert          Send alert when server certificate fails validation.\n");
    printf("  -checkOCSP Manually validate OCSP cert\n");

    printf("\n");
    printf("Deferred server certificate validation options:\n");
    printf("(incompatible with -autoSrvChk and -noSrvCertChk)\n");
    printf("  -iscRequestDeferredCredValidation Request deferred credential validation when opening the context handle\n");
    printf("  -achRequestDeferredCredValidation Request deferred credential validation when opening the credential handle\n");

    printf("\n");
    printf("Server Certificate revocation check options:\n");
    printf("(mutually exclusive)\n");
    printf("  -noRvcnChk      No revocation checking (default).\n");
    printf("  -RvcnChkChain   Check all certs in chain for revocation.\n");
    printf("  -RvcnChkEnd     Check only the last cert for revocation.\n");
    printf("  -RvcnChkNotRoot Do not check the root cert for revocation\n");

    printf("\n");
    printf("Client authentication options:\n");
    printf("  -u<user>        Name of user (in existing client certificate in user's My store)\n");
    printf("  -pfx:path       Specify path to pfx file for certificate store for client authentication.\n");
    printf("                  Will use certificate name specified by -u or the first certificate with key if -u is not specified\n");
    printf("  -c<mode>        Client authentication mode (default %d).\n", dwClientAuthMode);
    printf("                    0 = Webcli chooses cert using user name.\n");
    printf("                    1 = Default- Webcli chooses cert programmatically.\n");
    printf("                    2 = Webcli chooses cert using Cred Manager.\n");
    printf("                    3 = Schannel automatically chooses client cert.\n");
    printf("                    4 = Use pickled client certificate cred (use with -u).\n");
    printf("                    5 = Webcli picks cert from memory store\n");
    printf("                    6 = Webcli sets the PROV handle (use with -u).\n");
    printf("                    7 = Webcli will not send a certificate\n");
    printf("  -sendRoot       Send root cert in certificate message.\n");
    printf("  -prechkSrvCert  Check server cert chain before sending cert \n");
    printf("  -NoPostHandshakeAuth Prevent TLS 1.3 clients from sending the post_handshake_auth extension in the Client Hello.\n");

    printf("\n");
    printf("Other options:\n");
    printf("  -i<iter>        Fetches over same connection(default is 1)\n");
    printf("  -recnt          Reconnect following HTTP request (i times)\n");
    printf("  -renego         Renegotiate following HTTP request (i times)\n");
    printf("  -noRe           Disable session reconnects.\n");
    printf("  -sendCN         Send close_notify before closing connection\n");
    printf("  -newQOP         New QOP to generate alerts via EncryptMessage\n"
        "                  (This is the only method in kernel mode)\n");
    printf("  -m              Schannel automatically validates server certificate.\n"
        "                  (This overrides other flags)\n");
    printf("  -proxy          Connect via the proxy server.\n");
    printf("  -pkgs           List all packages (EnumerateSecurityPackages)\n");
    printf("  -ManCredVal     Set the  ISC_REQ_MANUAL_CRED_VALIDATION\n");
    printf("  -allocMem       Application allocates it's own memory\n");
    printf("  -allocSmall     Allocate own memory; initially allocate a small buffer, and realloc when we get a size\n");
    printf("  -SendExtraRecord   Check if Schannel needs to send extra record\n");
    printf("  -VerifyExtraRecord   Check if the peer has sent extra record\n");
    printf("  -MeasureTime       Check the response time of an SSL alert, in case server packet has bad padding\n");
    printf("  -b<option>      Encrypt buffer allocation options:\n");
    printf("                  0 = Contiguous\n");
    printf("                  1 = NonContiguous (separate buffers for header/message/trailer)\n");

    printf("  -EarlyStart:<flag>    Request to attempt Client side Early (false) Start\n");
    printf("                        1 = ENABLE_TLS_CLIENT_EARLY_START\n");
    printf("  -vfTrustedIssuersContainsAny:<CommonName1>[|<CommonNameN>]*  Verify that at least one of the entries for CN=<CommonName> are present in the "
        "trusted issuer list sent in certificate request. Multiple items delimited with \"|\". (requires -qctxt:3)\n");
    printf("  -vfTrustedIssuersNotContains:<CommonName1>[|<CommonNameN>]*  Verify that none of the entries for CN=<CommonName> are present in the "
        "trusted issuer list sent in certificate request. Multiple items delimited with \"|\". (requires -qctxt:3)\n");
    printf("  -ignoreHTTPError      Ignore HTTP status (200 OK/302 FOUND/etc\n");
    printf("  -AllowNullEncryption Allow cipher suites without encryption\n");
    printf("  -geExtensionType:<Generic Extension Type> Code point for generic extension to send\n");
    printf("  -geHandshakeType:<Handshake Type> Message type in which to send the generic extension\n");
    printf("  -geContents:<Contents> Contents of generic extension\n");
    printf("  -geExtensionTypeVerify:<Generic Extension Type> Code point for generic extension to verify\n");
    printf("  -geHandshakeTypeVerify:<Handshake Type> Message type in which to verify the generic extension\n");
    printf("  -geContentsVerify:<Contents> Contents of generic extension to verify\n");
    printf("  -AllowEarlyDisconnect Allows server-initiated closure of the TLS connection before receiving the HTTP response.\n");
    printf("  -EncryptAfterPostHandshake Client will encrypt and send some data after receiving SEC_I_RENEGOTIATE from DecryptMessage.\n");

    exit(1);
} // Usage

// webcli query and check options
#define SECPKG_ATTR_CIPHER_INFO_CIPHERSUITE   0x01
#define SECPKG_ATTR_CIPHER_INFO_KEYTYPE   0x02
#define SECPKG_ATTR_SESSION_INFO_FLAG 0x03
#define SECPKG_ATTR_SESSION_INFO_MACHINEID 0x04

// server certificate validation flags
int g_fNoSrvCertCheck = FALSE;
int g_fAutoServerCheck = TRUE;
int g_fNoSrvNameCheck = FALSE;
int g_fWinVerifyTrust = FALSE;  // use WinVerifyTrust

DWORD* g_dwClientSendOffSet = 0;
DWORD* g_dwClientRecvOffSet = 0;
DWORD* g_dwServerSendOffSet = 0;

RTL_CRITICAL_SECTION* g_WebDllCritSec;
CHAR** ClientSendBuffer;
DWORD* ClientSendSize;

CHAR** ServerSendBuffer;
DWORD* ServerSendSize;
void ResetGlobals();
DWORD* g_dwWebsrvStatus;
DWORD* g_dwWebcliStatus;

#define PKCS12_NAMED_NO_PERSIST_KEY 0x00020000  // PKCS12_NO_PERSIST_KEY and PKCS12_ALWAYS_CNG_KSP also need to be set

// maximum buffer size (16384 bytes)
#define MYMAX_BUFFER_LENGTH      0x4000  // setting a ceiling

#define COMBINEBYTES(hMsb, hLsb, Msb, Lsb)  ((DWORD)((DWORD) (((DWORD) (hMsb) << 24) | ((DWORD) (hLsb) << 16)))|((DWORD) (((DWORD) (Msb) << 8) | (DWORD) (Lsb))))

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
WebcliQueryAndCheck(
    IN     PCtxtHandle phContext);

DWORD
WebcliQueryContext(
    IN     PCtxtHandle phContext);

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
VOID
DbglibLocalFree(
    IN PVOID pBuffer
)
{
    LocalFree(pBuffer);
    pBuffer = NULL;
}

//++----------------------------------------------------------------------
//  NAME:  QueryCredentialsWrapper
//  
//  DESC:  QueryCredentialsAttributes calls
//  
//  ARGUMENTS: 
//  - DWORD dwCredAttr : attribute to query
//  - PCtxtHandle      : context handle (useless here)
//
//  RETURNS:   
//  - DWORD: status code
//  
//  NOTE:      
//--------------------------------------------------------------------++//
DWORD
QueryCredentialsWrapper(
    IN     DWORD       dwAttr,
    IN     PCredHandle phCred
)
{
    DWORD                          dwStatus = MYDBG_ERROR_ERROR;
    DWORD                          dwQueryAttr = dwAttr;
    PVOID                          pBuffer = NULL;
    ULONG                          dwMemSize = 0;
    PSecPkgCred_SupportedAlgs      pSuppAlgs = NULL;
    PSecPkgCred_CipherStrengths    pCiphStrgths = NULL;
    PSecPkgCred_SupportedProtocols pSuppProtocols = NULL;
    PSecPkgCredentials_Names       pNames = NULL;
    UINT                           uiCnt = 0;

    // figure out how much memory to allocate
    printf("- querying for cred attribute size.\n");

    // user mode attributes
    switch (dwAttr)
    {
    case SECPKG_ATTR_SUPPORTED_ALGS:
        dwMemSize = sizeof(SecPkgCred_SupportedAlgs);
        break;

    case SECPKG_ATTR_CIPHER_STRENGTHS:
        dwMemSize = sizeof(SecPkgCred_CipherStrengths);
        break;

    case SECPKG_ATTR_SUPPORTED_PROTOCOLS:
        dwMemSize = sizeof(SecPkgCred_SupportedProtocols);
        break;

    case SECPKG_CRED_ATTR_NAMES:
        dwMemSize = sizeof(SecPkgCredentials_Names);
        break;

    default:
        printf("- Unknown credentials attribute!\n");
        break;
    }

    // allocate memory for the buffer
    pBuffer = DbglibLocalAlloc(dwMemSize);
    if (NULL == pBuffer)
    {
        printf("- memory allocation for pBuffer FAILED!\n");
        dwStatus = MYDBG_ERROR_OUTOFMEMORY;
        goto cleanup;
    }

    //
    // call QueryCredentialsAttrbiutes
    //
    printf("- Querying user cred attr ID 0x%x\n", dwAttr);

    if (SEC_E_OK == dwStatus)
    {
        printf("- QContextA returned success for attr ID: 0x%x\n", dwAttr);

        // print useful info for each attribute
        switch (dwAttr)
        {
        case SECPKG_ATTR_SUPPORTED_ALGS:
            pSuppAlgs = (PSecPkgCred_SupportedAlgs)pBuffer;
            printf("- SECPKG_ATTR_SUPPORTED_ALGS:\n");
            printf("    No. of supported algorithms = %d\n", pSuppAlgs->cSupportedAlgs);
            printf("    Supported algorithms:\n");
            for (; uiCnt < pSuppAlgs->cSupportedAlgs; uiCnt++)
            {
                printf("\t 0x%x\n", pSuppAlgs->palgSupportedAlgs[uiCnt]);
            }
            break;

        case SECPKG_ATTR_CIPHER_STRENGTHS:
            pCiphStrgths = (PSecPkgCred_CipherStrengths)pBuffer;
            printf("- SECPKG_ATTR_CIPHER_STRENGTHS:");
            printf("    Cipher strengths: Min=%d, Max=%d\n",
                pCiphStrgths->dwMinimumCipherStrength,
                pCiphStrgths->dwMaximumCipherStrength);
            break;

        case SECPKG_ATTR_SUPPORTED_PROTOCOLS:
            pSuppProtocols = (PSecPkgCred_SupportedProtocols)pBuffer;
            printf("- SECPKG_ATTR_SUPPORTED_PROTOCOLS:\n");
            printf("    Supported Protocols:\n");

            if (pSuppProtocols->grbitProtocol & SP_PROT_TLS1_SERVER)
            {
                printf("\t SP_PROT_TLS1_SERVER\n");
            }
            if (pSuppProtocols->grbitProtocol & SP_PROT_SSL3_SERVER)
            {
                printf("\t SP_PROT_SSL3_SERVER\n");
            }
            if (pSuppProtocols->grbitProtocol & SP_PROT_SSL2_SERVER)
            {
                printf("\t SP_PROT_SSL2_SERVER\n");
            }
            if (pSuppProtocols->grbitProtocol & SP_PROT_PCT1_SERVER)
            {
                printf("\t SP_PROT_PCT1_SERVER\n");
            }

            break;

        case SECPKG_CRED_ATTR_NAMES:
            pNames = (PSecPkgCredentials_Names)pBuffer;
            printf("- SECPKG_CRED_ATTR_NAMES:\n");
            printf("    UserName is %s.\n", pNames->sUserName);
            break;

        default:
            printf("- Printing unsupported QueryCredentialsAttributes!\n");
            break;
        }
    }
    else
    {
        printf("- QueryCredentialsAttributes FAILED!\n");
        goto cleanup;
    }

cleanup:
    if (pBuffer)
    {
        DbglibLocalFree(pBuffer);
    }

    return dwStatus;

} // QueryCredentialsAttributes()


//++----------------------------------------------------------------------
// QUERYCREDENTIALSATTRIBUTES:
// All supported in user and kernel mode
// - SECPKG_ATTR_SUPPORTED_ALGS
// - SECPKG_ATTR_CIPHER_STRENGTHS
// - SECPKG_ATTR_SUPPORTED_PROTOCOLS
// - SECPKG_CRED_ATTR_NAMES: only server side
//--------------------------------------------------------------------++//
//++----------------------------------------------------------------------
//  NAME:  WebcliQueryCred
//
//  DESC:  calls the required QueryCredentialsAttributes calls
//
//  ARGUMENTS:
//  - PCredHandle : credentails handle
//
//  RETURNS:
//  - DWORD: status code
//
//  NOTE:
//--------------------------------------------------------------------++//
DWORD
WebcliQueryCred(
    IN     PCredHandle phCreds)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;
    DWORD  dwAttr = 0;

    // Now get some info on the securitycontexts
    if (g_fQueryAllCreds || g_fQuerySuppAlgs)
    {
        dwAttr = SECPKG_ATTR_SUPPORTED_ALGS;
        dwStatus = QueryCredentialsWrapper(dwAttr, phCreds);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fQueryAllCreds || g_fQueryCiphStrgths)
    {
        dwAttr = SECPKG_ATTR_CIPHER_STRENGTHS;
        dwStatus = QueryCredentialsWrapper(dwAttr, phCreds);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fQueryAllCreds || g_fQuerySuppProtocols)
    {
        dwAttr = SECPKG_ATTR_SUPPORTED_PROTOCOLS;
        dwStatus = QueryCredentialsWrapper(dwAttr, phCreds);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fQueryAllCreds || g_fQueryCredNames)
    {
        dwAttr = SECPKG_CRED_ATTR_NAMES;
        dwStatus = QueryCredentialsWrapper(dwAttr, phCreds);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    dwStatus = MYDBG_SUCCESS;

cleanup:

    return dwStatus;
}

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

    //=======================================================================
    // these attrbiutes are supported in both user and kernel mode
    //=======================================================================
    // SECPKG_ATTR_CONNECTION_INFO
    if (g_fQryCtxtAll || g_fQryCtxtConnInfo)
    {
        dwAttr = SECPKG_ATTR_CONNECTION_INFO;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    //  SECPKG_ATTR_SIZES
    //  SECPKG_ATTR_STREAM_SIZES
    if (g_fQryCtxtAll || g_fQryCtxtSizes)
    {
        if (g_fConnectionMode)
        {
            dwAttr = SECPKG_ATTR_SIZES;
        }
        else
        {
            dwAttr = SECPKG_ATTR_STREAM_SIZES;
        }
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    // SECPKG_ATTR_APPLICATION_PROTOCOL
    if (g_fQryCtxtAll || g_fQryCtxtApplicationProtocol)
    {
        dwAttr = SECPKG_ATTR_APPLICATION_PROTOCOL;
        printf("Calling QCA - SECPKG_ATTR_APPLICATION_PROTOCOL \n");
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    //=======================================================================
    // these attrbiutes are supported in user mode only
    //=======================================================================
    // SECPKG_ATTR_ISSUER_LIST_EX
    if (g_fQryCtxtAll || g_fQryCtxtIssrListEx)
    {
        dwAttr = SECPKG_ATTR_ISSUER_LIST_EX;
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_REMOTE_CERT_CONTEXT
    if (g_fQryCtxtAll || g_fQryCtxtRemoteCert)
    {
        dwAttr = SECPKG_ATTR_REMOTE_CERT_CONTEXT;
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_LOCAL_CERT_CONTEXT
    if (g_fQryCtxtAll || g_fQryCtxtLocalCert)
    {
        dwAttr = SECPKG_ATTR_LOCAL_CERT_CONTEXT;
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_SESSION_INFO
    if (g_fQryCtxtAll || g_fQryCtxtSessInfo)
    {
        dwAttr = SECPKG_ATTR_SESSION_INFO;
        dwStatus = QueryContextWrapper(dwAttr,phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_KEY_INFO
    if (g_fQryCtxtAll || g_fQryCtxtKeyInfo)
    {
        dwAttr = SECPKG_ATTR_KEY_INFO;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_PROTO_INFO
    if (g_fQryCtxtAll || g_fQryCtxtProtoInfo)
    {
        dwAttr = SECPKG_ATTR_PROTO_INFO;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_EAP_KEY_BLOCK
    if (g_fQryCtxtAll || g_fQryCtxtEapKeyBlock)
    {
        dwAttr = SECPKG_ATTR_EAP_KEY_BLOCK;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    //=======================================================================
    // these attrbiutes are supported in kernel mode only
    //=======================================================================
    // 

    // SECPKG_ATTR_REMOTE_CERTIFICATES
    if (g_fQryCtxtAll)
    {
        dwAttr = SECPKG_ATTR_REMOTE_CERTIFICATES;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_LOCAL_CERT_INFO
    if (g_fQryCtxtAll)
    {
        dwAttr = SECPKG_ATTR_LOCAL_CERT_INFO;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_SESSION_KEY
    if (g_fQryCtxtAll)
    {
        dwAttr = SECPKG_ATTR_SESSION_KEY;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    // SECPKG_ATTR_CC_POLICY_RESULT
    if (g_fQryCtxtAll)
    {
        dwAttr = SECPKG_ATTR_CC_POLICY_RESULT;
        dwStatus = QueryContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

cleanup:

    return dwStatus;
} // WebcliQueryContext

DWORD
WebcliQueryCred(
    IN     PCredHandle phCreds);

//++----------------------------------------------------------------------
//  NAME:  WebcliSetContext
//
//  DESC:  Sets the required SetContextAttributes calls
//
//  ARGUMENTS:
//  - PCredHandle : credentails handle
//
//  RETURNS:
//  - DWORD: status code
//
//  NOTE:
//--------------------------------------------------------------------++//
DWORD
WebcliSetContext(
    IN     PCtxtHandle phContext)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;
    DWORD  dwAttr = 0;
    INT         iCounter = 0;

    // Now get some info on the securitycontexts
    if (g_fSetAppData || g_fSetCtxtAll)
    {
        dwAttr = SECPKG_ATTR_APP_DATA;
        printf("Calling SCA - SECPKG_ATTR_APP_DATA \n");
        dwStatus = SetContextWrapper(dwAttr, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fSetEAPProtocol || g_fSetCtxtAll)
    {
        dwAttr = SECPKG_ATTR_EAP_PRF_INFO;
        printf("Calling SCA - SECPKG_ATTR_EAP_PRF_INFO with EAP PRF 0x%x\n", g_dwSetEapPRF);

        if (g_dwSetEapPRF == MAX_EAP_PRF)
        {
            for (iCounter = 0; iCounter < MAX_EAP_PRF; iCounter++)
            {
                g_dwSetEapPRF = iCounter;
                dwStatus = SetContextWrapper(dwAttr, phContext);
                if (SEC_E_OK != dwStatus)
                {
                    goto cleanup;
                }

                g_fQryCtxtEapKeyBlock = TRUE;
                dwStatus = WebcliQueryContext(phContext);
                if (SEC_E_OK != dwStatus)
                {
                    goto cleanup;
                }
            }
        }
        else
        {
            dwStatus = SetContextWrapper(dwAttr, phContext);
            if (SEC_E_OK != dwStatus)
            {
                goto cleanup;
            }
        }
    }
    if (g_fSetKeyingMaterialInfo || g_fSetCtxtAll)
    {
        printf("Calling SCA - SECPKG_ATTR_KEYING_MATERIAL_INFO \n");
        dwStatus = SetContextWrapper(SECPKG_ATTR_KEYING_MATERIAL_INFO, phContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    dwStatus = MYDBG_SUCCESS;

cleanup:

    return dwStatus;
}

unsigned long SendToServer(CHAR* pbData, unsigned long cbData)
{

    EnterCriticalSection(g_WebDllCritSec);

    //
    // Send this data to the server.
    //
    ClientSendSize[*g_dwClientSendOffSet] = cbData;
    memcpy(ClientSendBuffer[*g_dwClientSendOffSet], pbData, cbData);

    //
    // Now increment the client send count.
    //
    *g_dwClientSendOffSet = *g_dwClientSendOffSet + 1;


    // memcpy(g_pbSharedData,pbData,*g_cbSharedData);

    g_dwNumServerSends++;

    LeaveCriticalSection(g_WebDllCritSec);

    return cbData;
}


unsigned long ReceiveFromServer(CHAR* pbData, unsigned long cbData)
{
    //
    // Wait till we receive data from the server.
    //
    while (*g_dwClientRecvOffSet == *g_dwServerSendOffSet)
    {
        if ((*g_dwWebsrvStatus == WEBSRV_WEBCLI_COMPLETED) || (*g_dwWebcliStatus == WEBSRV_WEBCLI_COMPLETED))
        {
            printf("Exiting webcli...\n");
            return 0;
        }
        Sleep(50);
    }

    EnterCriticalSection(g_WebDllCritSec);

    //
    // Copy it to the buffers.
    //
    cbData = ServerSendSize[*g_dwClientRecvOffSet];
    memcpy(pbData, ServerSendBuffer[*g_dwClientRecvOffSet], cbData);
    *g_dwClientRecvOffSet = *g_dwClientRecvOffSet + 1;

    LeaveCriticalSection(g_WebDllCritSec);
    return cbData;
}

/*********************************************************************
 MAIN: Webclient works from here
*********************************************************************/
int main(int argc, char* argv[])
{
    unsigned long  dwStatus = MYDBG_ERROR_ERROR;
    INT     i = 0;
    INT     iOption = 0;
    PCHAR   pszOption = NULL;
    PCHAR   pszValue = NULL;
    WSADATA WsaData = { 0 };
    unsigned long   dwLogLevel = DEBUG_LOG_ERROR;
    BOOL    fRvcnChkSelected = FALSE;

    printf("Using Sockets...\n");

    //
    // Parse the command line.
    //

    if (argc <= 1)
    {
        Usage();
        goto cleanup;
    }

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '/')
        {
            argv[i][0] = '-';
        }
        if (argv[i][0] != '-')
        {
            printf("\n**** Invalid argument \"%s\".\n", argv[i]);
            Usage();
        }

        //
        // Parse word-based options.
        //

        pszOption = &argv[i][1];

        pszValue = strchr(pszOption, ':');

        if (pszValue != NULL)
        {
            // two-part argument
            *pszValue = '\0';
            pszValue++;
        }

        // if target SSL server name is different from DNS server name
        if (_strcmpi(pszOption, "target") == 0)
        {
            g_pszTargetName = pszValue;
            continue;
        }

        // to display output from EnumerateSecurityPackages
        if (_strcmpi(pszOption, "pkgs") == 0)
        {
            g_fPackageInfo = TRUE;
            continue;
        }

        // stream mode
        if (_stricmp(pszOption, "stream") == 0)
        {
            g_fConnectionMode = FALSE;
            continue;
        }

        // connection mode
        if (_stricmp(pszOption, "connection") == 0)
        {
            g_fConnectionMode = TRUE;
            continue;
        }

        // Disables the TLS 1.3+ record layer
        if (_stricmp(pszOption, "NoRecordLayer") == 0)
        {
            g_fNoRecordLayer = TRUE;
            continue;
        }

        // Expected server speaks first message contents
        if (_strcmpi(pszOption, "vfServerSpeaksFirst") == 0)
        {
            g_pszServerSpeaksFirst = pszValue;
            continue;
        }

        // for site compat/interop client
        if (_stricmp(pszOption, "reset") == 0)
        {
            ResetGlobals();
            g_fCompatCliMode = TRUE;
            g_dwNumServerSends = 0;
            memset(g_pszNegotiatedCipherSuite, 0, 256 * sizeof(wchar_t));
            memset(g_pszNegotiatedProtocol, 0, 256 * sizeof(char));
            continue;
        }

        // renegotiation: have to keep connection alive
        if (_strcmpi(pszOption, "renego") == 0)
        {
            g_fRenegotiate = TRUE;
            g_fKeepAlive = TRUE; // to keep connection alive
            g_dwIterationCount = 2;    // to force second fetch
            continue;
        }

        // reconnection, have to keep connection alive
        if (_strcmpi(pszOption, "recnt") == 0)
        {
            g_fReconnect = TRUE;
            g_fKeepAlive = TRUE;
            continue;
        }

        // routing via proxy server
        if (_strcmpi(pszOption, "proxy") == 0)
        {
            fUseProxy = TRUE;
            continue;
        }

        // no server certificate validation
        if (_strcmpi(pszOption, "noSrvCertChk") == 0)
        {
            g_fNoSrvCertCheck = TRUE;
            continue;
        }

        // check for OCSP stapling
        if (_strcmpi(pszOption, "checkOCSP") == 0)
        {
            g_fCheckOcsp = TRUE;
            continue;
        }

        // let Schannel automatically validate server certificate
        if (_strcmpi(pszOption, "autoSrvChk") == 0)
        {
            g_fAutoServerCheck = TRUE;
            continue;
        }

        // Schannel will not compare supplied target name with
        // subject name in server certificate
        if (_strcmpi(pszOption, "noSrvNameChk") == 0)
        {
            g_fNoSrvNameCheck = TRUE;
            // only valid with g_fAutoServerCheck
            if (g_fAutoServerCheck == FALSE)
            {
                printf("  Option \"noSrvNameChk\" is only valid with \"autoSrvChk\".\n");
                Usage();
            }
            continue;
        }

        // Checks that the certificate presented by the server matches the following
        // subject name.
        if (_strcmpi(pszOption, "verifySrvSubjectName") == 0)
        {
            g_pszSrvCertNameToVerify = pszValue;
            continue;
        }

        // use WinVerifyTrust to manually validate server cert
        if (_strcmpi(pszOption, "wvt") == 0)
        {
            g_fWinVerifyTrust = TRUE;
            continue;
        }

        // send alert if server certificate fails validation
        if (_strcmpi(pszOption, "alert") == 0)
        {
            g_fSendAlert = TRUE;
            continue;
        }

        // send root certificate in certificate message
        if (_stricmp(pszOption, "sendRoot") == 0)
        {
            g_dwSendRootCert = SCH_SEND_ROOT_CERT;
            continue;
        }

        // check server cert before sending cli cert
        if (_stricmp(pszOption, "prechkSrvCert") == 0)
        {
            g_fPrecheckSrvCert = TRUE;
            continue;
        }


        // server cert revocation check done on chain
        if (!fRvcnChkSelected && _strcmpi(pszOption, "RvcnChkChain") == 0)
        {
            dwSrvCertRvcnOpt = SCH_CRED_REVOCATION_CHECK_CHAIN;
            fRvcnChkSelected = TRUE;
            continue;
        }

        // server cert revocation check done on last cert in chain
        if (!fRvcnChkSelected && _strcmpi(pszOption, "RvcnChkEnd") == 0)
        {
            dwSrvCertRvcnOpt = SCH_CRED_REVOCATION_CHECK_END_CERT;
            fRvcnChkSelected = TRUE;
            continue;
        }

        // server cert revocation check done on chain except root cert
        if (!fRvcnChkSelected && _strcmpi(pszOption, "RvcnChkNotRoot") == 0)
        {
            dwSrvCertRvcnOpt = SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
            fRvcnChkSelected = TRUE;
            continue;
        }

        // send close_notify after every reconnection
        if (_strcmpi(pszOption, "sendCN") == 0)
        {
            g_fSendCloseNotify = TRUE;
            continue;
        }

        // SSPI app allocs it's own memory
        if (_strcmpi(pszOption, "allocMem") == 0)
        {
            g_fAllocateMemory = TRUE;
            continue;
        }

        // SSPI app allocs it's own memory; initially too small, then realloc when we get a size
        if (_strcmpi(pszOption, "allocSmall") == 0)
        {
            g_fAllocateMemory = TRUE;
            g_fUseSmallBuffer = TRUE;
            continue;
        }

        // restrict ciphers - currently blocks use of RC4
        if (_strcmpi(pszOption, "restrictCiphers") == 0)
        {
            g_fUseSecureCiphers = TRUE;
        }

        // use the new QOP to generate Alerts (only method in kernel mode)
        if (_strcmpi(pszOption, "newQOP") == 0)
        {
            g_fUseNewQOP = TRUE;
            continue;
        }
        // disable session reconnects
        if (_stricmp(pszOption, "noRe") == 0)
        {
            g_fDisableReconnects = TRUE;
            continue;
        }
        //
        // 
        //
        if (_strcmpi(pszOption, "ManCredVal") == 0)
        {
            g_fManualCredValidation = TRUE;
            continue;
       }
        // Test empty message
        if (_strcmpi(pszOption, "TestEmptyMessage") == 0)
        {
            g_ftestEmptyMessage = TRUE;
            continue;
        }

        // SetContextAttributes options
        if (_strcmpi(pszOption, "sctxt") == 0)
        {
            g_fQryCtxtCipherInfo = FALSE;
            // atoi for NULL returns 0, taken care of that
            switch (atoi(pszValue))
            {
            case 0:
                // This will set even the Eap PRF
                g_fSetCtxtAll = TRUE;
                break;
            case 1:
                g_fSetAppData = TRUE;
                break;
            case 2:
                g_fSetKeyingMaterialInfo = TRUE;
                break;
            default:
                printf("\n**** Invalid SetContextAttributes option.\n");
                Usage();
            }
            continue;
        }

        // SetContextAttributes options
        if (_strcmpi(pszOption, "sEap") == 0)
        {
            g_fQryCtxtCipherInfo = FALSE;
            g_fSetEAPProtocol = TRUE;
            g_dwSetEapPRF = atoi(pszValue);
            continue;
        }

        // Set EarlyStart options
        if (_strcmpi(pszOption, "EarlyStart") == 0)
        {
            g_fEarlyStartRequested = TRUE;
            switch (atoi(pszValue))
            {
            case 1:
                g_fSetTlsClientEarlyStart = TRUE;
                break;
            default:
                printf("\n**** Invalid EarlyStart option.\n");
                Usage();
            }
            continue;
        }

        // QueryContextAttributes options
        if (_strcmpi(pszOption, "qctxt") == 0)
        {
            g_fQryCtxtCipherInfo = FALSE;
            // atoi for NULL returns 0, taken care of that
            switch (atoi(pszValue))
            {
            case 0:
                g_fQryCtxtAll = TRUE;
                break;
            case 1:
                g_fQryCtxtConnInfo = TRUE;
                break;
            case 2:
                g_fQryCtxtSizes = TRUE;
                break;
            case 3:
                g_fQryCtxtIssrListEx = TRUE;
                break;
            case 4:
                g_fQryCtxtRemoteCert = TRUE;
                break;
            case 5:
                g_fQryCtxtLocalCert = TRUE;
                break;
            case 6:
                g_fQryCtxtSessInfo = TRUE;
                break;
            case 7:
                g_fQryCtxtKeyInfo = TRUE;
                break;
            case 8:
                g_fQryCtxtProtoInfo = TRUE;
                break;
            case 9:
                g_fQryCtxtEapKeyBlock = TRUE;
                break;
            case 15:
                g_fQryCtxtCipherInfo = TRUE;
                break;
            case 16:
                g_fQryCtxtAppData = TRUE;
                break;
            case 17:
                g_fQryCtxtLifeSpan = TRUE;
                break;
            case 18:
                g_fQryCtxtNames = TRUE;
                break;
            case 20:
                g_fQryCtxtSupportedSignatures = TRUE;
                break;
            case 21:
                g_fQryCtxtApplicationProtocol = TRUE;
                break;
            case 23:
                g_fQryCtxtAuthority = TRUE;
                break;
            case 26:
                g_fQryCtxtKeyingMaterialInproc = TRUE;
                break;
            case 27:
                g_fQryCtxtKeyingMaterial = TRUE;
                break;
            case 28:
                g_fQryCtxtCertValidationResult = TRUE;
                break;
            case 29:
                g_fQryCtxtCertValidationResultInProc = TRUE;
                break;
            case 30:
                g_fQryCtxtSerializedRemoteCertInProc = TRUE;
                break;
            case 31:
                g_fQryCtxtSerializedRemoteCert = TRUE;
                break;
            default:
                printf("\n**** Invalid QueryContextAttributes option.\n");
                Usage();
            }
            continue;
        }

        // QueryCredentialsAttributes options
        if (_strcmpi(pszOption, "qcred") == 0)
        {
            // atoi for NULL returns 0, taken care of that
            switch (atoi(pszValue))
            {
            case 0:
                g_fQueryAllCreds = TRUE;
                break;
            case 1:
                g_fQuerySuppAlgs = TRUE;
                break;
            case 2:
                g_fQueryCiphStrgths = TRUE;
                break;
            case 3:
                g_fQuerySuppProtocols = TRUE;
                break;
            case 4:
                g_fQueryCredNames = TRUE;
                break;
            default:
                printf("\n**** Invalid QueryCredentialsAttributes option.\n");
                Usage();
            }
            continue;
        }

        if (_strcmpi(pszOption, "hash") == 0)
        {
            if (g_cSupportedAlgs >= MAX_SUPPORTED_ALGORITHMS)
            {
                printf("\n**** Invalid number of algorithms specified, currently only %d are supported\n", MAX_SUPPORTED_ALGORITHMS);
                Usage();
            }
            // atoi for NULL returns 0, taken care of that
            switch (atoi(pszValue))
            {
            case 1:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_SHA;
                break;
            case 2:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_MD5;
                break;
            case 3:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_SHA_256;
                break;
            case 4:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_SHA_384;
                break;
            case 5:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_SHA_512;
                break;
            default:
                printf("\n**** Invalid hash algorithm option.\n");
                Usage();
            }
            continue;
        }

        //
        // Parse letter-based options.
        //

        iOption = argv[i][1];
        pszValue = &argv[i][2];
        if (pszValue == NULL)
        {
            printf("\n*** Invalid argument to -%c\n", iOption);
            Usage();
        }

        switch (iOption)
        {
        case '?':
            Usage();
            goto cleanup;

        case 's':
            if (_strcmpi(pszValue, "") == 0)
            {
                printf("\nInvalid argument to -%c\n", iOption);
                Usage();
            }
            g_pszServerName = pszValue;
            break;
        case 'r':
            if (_strcmpi(pszValue, "") == 0)
            {
                printf("\nInvalid argument to -%c\n", iOption);
                Usage();
            }
            g_pszSecondServerName = pszValue;
            g_fReconnectToSecondServer = TRUE;
            break;

        case 'p':
            iPortNumber = atoi(pszValue);
            break;

        case 'i':
            g_dwIterationCount = atoi(pszValue);
            if (g_dwIterationCount > 1)
            {
                g_fKeepAlive = TRUE;
            }
            break;

        case 'f':
            pszFileName = pszValue;
            break;

        case 'o':
            pszReceivedFileName = pszValue;
            g_fSaveReceivedFile = TRUE;
            break;

        case 'b':
            switch (atoi(pszValue))
            {
            case 0:
                //contiguous buffers
                g_fNonContiguousBuffers = FALSE;
                break;
            case 1:
                //non-contiguous, separate for each
                g_fNonContiguousBuffers = TRUE;
                break;
            case 2:
                printf("\n*** Invalid buffer allocation type arg to -b\n");
                goto cleanup;
                break;
            }
            break;

        case 'P':

            if (g_dwDisabledProtocols > 0)
            {
                printf("\n**** -P and -D cannot be specified together.\n");
                Usage();
                break;
            }

            switch (atoi(pszValue))
            {
            case 0:
                g_dwProtocol |= SP_PROT_ALL;
                break;
            case 1:
                g_dwProtocol |= SP_PROT_PCT1;
                break;
            case 2:
                g_dwProtocol |= SP_PROT_SSL2;
                break;
            case 3:
                g_dwProtocol |= SP_PROT_SSL3;
                break;
            case 4:
                g_dwProtocol |= SP_PROT_TLS1_0;
                break;
            case 5:
                g_dwProtocol |= SP_PROT_TLS1_1;
                break;
            case 6:
                g_dwProtocol |= SP_PROT_TLS1_2;
                break;
            case 7:
                g_dwProtocol |= SP_PROT_TLS1_3;
                break;
            default:
                printf("\n*** Invalid protocol argument to -P\n");
                goto cleanup;
                break;
            }

            g_fUseSchCredentials = FALSE;
            break;

        case 'D':

            if (g_dwProtocol > 0)
            {
                printf("\n**** -P and -D cannot be specified together.\n");
                Usage();
                break;
            }

            switch (atoi(pszValue)) {
            case 0:
                break;
            case 1:
                g_dwDisabledProtocols |= SP_PROT_PCT1;
                break;
            case 2:
                g_dwDisabledProtocols |= SP_PROT_SSL2;
                break;
            case 3:
                g_dwDisabledProtocols |= SP_PROT_SSL3;
                break;
            case 4:
                g_dwDisabledProtocols |= SP_PROT_TLS1_0;
                break;
            case 5:
                g_dwDisabledProtocols |= SP_PROT_TLS1_1;
                break;
            case 6:
                g_dwDisabledProtocols |= SP_PROT_TLS1_2;
                break;
            case 7:
                g_dwDisabledProtocols |= SP_PROT_TLS1_3;
                break;
            default:
                printf("\n**** Invalid protocol specified to -D.\n");
                Usage();
                break;
            }

            g_fUseSchCredentials = TRUE;
            break;

        case 'E':
            if (g_cSupportedAlgs >= MAX_SUPPORTED_ALGORITHMS)
            {
                printf("\n**** Invalid number of algorithms specified, currently only %d are supported\n", MAX_SUPPORTED_ALGORITHMS);
                Usage();
            }
            switch (atoi(pszValue))
            {
            case 1:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_RSA_KEYX;
                break;
            case 2:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_DH_EPHEM;
                break;
            case 3:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_ECDH_EPHEM;
                break;
            default:
                printf("\nInvalid key exchange argument to -E\n");
                goto cleanup;
                break;
            }
            break;

        case 'C':
            if (g_cSupportedAlgs >= MAX_SUPPORTED_ALGORITHMS)
            {
                printf("\n**** Invalid number of algorithms specified, currently only %d are supported\n", MAX_SUPPORTED_ALGORITHMS);
                Usage();
            }
            switch (atoi(pszValue))
            {
            case 1:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_RC4;
                break;
            case 2:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_RC2;
                break;
            case 3:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_DES;
                break;
            case 4:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_3DES;
                break;
            case 5:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_AES_128;
                break;
            case 6:
                g_rgbSupportedAlgs[g_cSupportedAlgs++] = CALG_AES_256;
                break;
            default:
                printf("\n**** Invalid symmetric algorithm specified to -C.\n");
                Usage();
                break;
            }
            break;

            // setting MINIMUM cipher strength
        case 'n':
            g_dwMinCipherStrength = atoi(pszValue);
            break;

            // setting MAXIMIM cipher strength
        case 'N':
            g_dwMaxCipherStrength = atoi(pszValue);
            break;

        case 'm':
            g_fMutualAuth = TRUE;
            break;

        case 'c':
            dwClientAuthMode = atoi(pszValue);
            break;

        case 'u':
            if (_strcmpi(pszValue, "") == 0)
            {
                printf("\nInvalid argument to -%c. "
                    "No user name specified!\n", iOption);
                Usage();
            }
            else if (_strcmpi(pszValue, "EmptyCN") == 0)
            {
                g_pszUserName = (LPSTR)"";
            }
            else
            {
                g_pszUserName = pszValue;
            }

            if (dwClientAuthMode == CLIENT_AUTH_DEFAULT_MODE)
            {
                dwClientAuthMode = CLIENT_AUTH_MANUAL;
            }
            break;

        default:
            printf(__FUNCTION__":**** Error- Invalid option \"%s\"\n", argv[i]);
            Usage();
            goto cleanup;
        } // end switch(iOption)

    } // end for(argc)

    // Webcli's manual cred validation is not implemented KM so default is to use schannel's
    // validation, unless we are doing deferred cred validation.

    if ((g_fIscReqDeferredCredValidation || g_fAchReqDeferredCredValidation) &&
        (g_fAutoServerCheck || g_fNoSrvCertCheck))
    {
        printf(__FUNCTION__":**** Error- Invalid combination of parameters, cannot have DeferredCredValidation when -autoSrvChk or -noSrvCertChk are set.\n");
        Usage();
        goto cleanup;
    }

    if (g_fQryCtxtSerializedRemoteCertInProc &&
        (g_fAutoServerCheck || g_fNoSrvCertCheck))
    {
        printf(__FUNCTION__":**** Error- Invalid combination of parameters, cannot validate "
            "SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT_INPROC when -autoSrvChk or -noSrvCertChk are set.\n");
        Usage();
        goto cleanup;
    }

    // Validate async SSPI-related parameters.

    // if no target name is input, then server name is target
    if (g_pszTargetName == NULL)
    {
        g_pszTargetName = g_pszServerName;
    }

    //
    // Initialize the WinSock subsystem.
    //

    if (!g_fSocketStarted)
    {
        if (WSAStartup(WINSOCK_VERSION_USED, &WsaData) == SOCKET_ERROR)
        {
            printf("- Error %d returned by WSAStartup\n", GetLastError());
            goto cleanup;
        }
        g_fSocketStarted = TRUE;
    }

    //
    // call Webclient
    //
    dwStatus = WebClient();

cleanup:

    // Shutdown WinSock subsystem.
    WSACleanup();
    g_fSocketStarted = FALSE;

    return dwStatus;
} // main()

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
    LPSTR   pszProxyServer = (LPSTR)"myproxy";  // proxy server
    INT     iProxyPort = 80;          // proxy server port
    INT rc = 0;
    INT tempPort = 0;
    DWORD dwTimeout = 30 * 1000; //30 seconds
    BOOL fSuccess = FALSE;
    struct addrinfo* result = NULL,
        * temp = NULL;

    *pSocket = INVALID_SOCKET;

    // use proxy if specified
    if (fUseProxy)
    {
        tempPort = iProxyPort;
        rc = getaddrinfo(pszProxyServer, NULL, NULL, &result);
    }
    else
    {
        tempPort = iPortNumber;
        rc = getaddrinfo(pszServerName, NULL, NULL, &result);
    }

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

    if (fUseProxy)
    {
        BYTE  pbMessage[200];

        unsigned long cbMessage;

        // Build message for proxy server
        strcpy((LPSTR)pbMessage, "CONNECT ");
        strcat((LPSTR)pbMessage, pszServerName);
        strcat((LPSTR)pbMessage, ":");
        _itoa(iPortNumber, (LPSTR)pbMessage + strlen((LPSTR)pbMessage), 10);
        strcat((LPSTR)pbMessage, " HTTP/1.0\r\nUser-Agent: webclient\r\n\r\n");
        cbMessage = strlen((LPCSTR)pbMessage);

        // Send message to proxy server
        if (send(Socket, (LPCSTR)pbMessage, cbMessage, 0) == SOCKET_ERROR)
        {
            printf("- Error %d sending message to proxy!\n", WSAGetLastError());
            if (shutdown(Socket, SD_BOTH))
            {
                printf("- Error %d in Socket shutdown!\n", WSAGetLastError());
                return WSAGetLastError();
            }
            // close the socket, returns 0 for success
            if (closesocket(Socket))
            {
                printf("- Error %d on Socket close!\n", WSAGetLastError());
                return WSAGetLastError();
            }
            Socket = INVALID_SOCKET;
            return WSAGetLastError();
        }

        // Receive message from proxy server
        if (fUseSockets)
        {
            cbMessage = recv(Socket, (LPSTR)pbMessage, 200, 0);
        }
        else
        {
            cbMessage = ReceiveFromServer((LPSTR)pbMessage, 200);
        }

        if (cbMessage == SOCKET_ERROR)
        {
            printf("- Error %d receiving message from proxy!\n", WSAGetLastError());
            return WSAGetLastError();
        }

        // BUGBUG - should continue to receive until CR LF CR LF is received
    }

    if (pSocket != NULL)
    {
        *pSocket = Socket;
    }

    return MYDBG_SUCCESS;
} // ConnectToServer()


//++----------------------------------------------------------------------
//  NAME:  QueryAndCheckContextWrapper
//
//  DESC:  wraps the QueryContextAttributes calls and checks for an
//          expected result.
//
//  ARGUMENTS:
//  - DWORD dwAttr      :   attribute to query
//  - PCtxtHandle       :   context handle (useless here)
//  - dwCheckAttribute  :   Attribute type to be checked
//  - dwExpected        :   Expected value for the attribute
//  RETURNS:
//  - DWORD: status code
//
//  NOTE:
//--------------------------------------------------------------------++//
DWORD
QueryAndCheckContextWrapper(
    IN     DWORD       dwAttr,
    IN     PCtxtHandle phContext,
    IN     DWORD       dwCheckAttribute,
    IN     DWORD       dwExpected
)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;
    DWORD  dwQueryAttr = 0;
    PVOID  pvBuffer = NULL;
    ULONG  dwMemSize = 0;
    PSecPkgContext_CipherInfo pCipherInfo = NULL;
    PSecPkgContext_SessionInfo pSessionInfo = NULL;

    //=======================================================================
    // figure out how much memory to allocate and allocate it
    //=======================================================================
    switch (dwAttr)
    {
    case SECPKG_ATTR_SESSION_INFO:
        dwMemSize = sizeof(SecPkgContext_SessionInfo);
        break;

    case SECPKG_ATTR_CIPHER_INFO:
        dwMemSize = sizeof(SecPkgContext_CipherInfo);
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
           pvBuffer
    );


    if (SEC_E_OK == dwStatus)
    {
        printf("- QContextA returned success for attr ID: 0x%x\n", dwAttr);

        //===================================================================
        // print useful info for each attribute
        //===================================================================
        switch (dwAttr)
        {
        case SECPKG_ATTR_SESSION_INFO:
            pSessionInfo = (PSecPkgContext_SessionInfo)pvBuffer;
            printf("- SECPKG_ATTR_SESSION_INFO:\n");
            printf("  Session Flags         : %x\n", pSessionInfo->dwFlags);
            printf("  Machine ID            : %x\n",
                COMBINEBYTES(
                    pSessionInfo->rgbSessionId[4],
                    pSessionInfo->rgbSessionId[5],
                    pSessionInfo->rgbSessionId[6],
                    pSessionInfo->rgbSessionId[7]));
            if (dwCheckAttribute == SECPKG_ATTR_SESSION_INFO_FLAG)
            {
                if (pSessionInfo->dwFlags == dwExpected)
                {
                    printf("  The Reconnect Flag is SET and a reconnect was performed \n");

                }
                else // did not match expected result
                {
                    printf("  The Reconnect Failed and a FULL handshake was performed \n");
                    dwStatus = MYDBG_ERROR_ERROR;
                }
            }
            if (dwCheckAttribute == SECPKG_ATTR_SESSION_INFO_MACHINEID)
            {
                dwQueryAttr = COMBINEBYTES(
                    pSessionInfo->rgbSessionId[4],
                    pSessionInfo->rgbSessionId[5],
                    pSessionInfo->rgbSessionId[6],
                    pSessionInfo->rgbSessionId[7]);
                if (dwQueryAttr == dwExpected)
                {
                    printf("  Machine IDs match %x : %x ", dwQueryAttr, dwExpected);
                }
                else // did not match expected result
                {
                    printf("  Machine ID match FAILED %x : %x \n", dwQueryAttr, dwExpected);
                    dwStatus = MYDBG_ERROR_ERROR;
                }
            }

            break;

        case SECPKG_ATTR_CIPHER_INFO:
            pCipherInfo = (PSecPkgContext_CipherInfo)pvBuffer;
            printf("- SECPKG_ATTR_CIPHER_INFO:\n");

            printf("  Ciphersuite         : %x %wS\n",
            pCipherInfo->dwCipherSuite,
            pCipherInfo->szCipherSuite);
            
            if (pCipherInfo->dwKeyType != 0)
            {
                printf("  KeyType             : %d\n", pCipherInfo->dwKeyType);
            }

            if (dwCheckAttribute == SECPKG_ATTR_CIPHER_INFO_CIPHERSUITE)
            {
                if (pCipherInfo->dwCipherSuite == dwExpected)
                {
                    printf("  Ciphersuite used matched ciphersuite expected\n");

                }
                else // Ciphersuite did not match expected result
                {
                    printf(" Ciphersuite used does not match ciphersuite expected\n");
                    dwStatus = MYDBG_ERROR_ERROR;
                }
            }
            if (dwCheckAttribute == SECPKG_ATTR_CIPHER_INFO_KEYTYPE)
            {
                if (pCipherInfo->dwKeyType == dwExpected)
                {
                    printf("  KeyType used matched KeyType expected\n");
                }
                else // KeyType did not match expected result
                {
                    printf(" KeyType used %d does not match KeyType expected %d\n", pCipherInfo->dwKeyType, dwExpected);
                    dwStatus = MYDBG_ERROR_ERROR;
                }
            }
            break;

        default:
            printf("- Attribute not supported.\n");
            break;
        }
    }
    else
    {
        printf("- QueryContextAttributes failed for attr ID 0x%x\n", dwAttr);

        switch (dwAttr)
        {
        default:
            printf("- QContextA FAILED unexpectedly!.\n");
            //PrintSecurityError(dwStatus);
            break;
        }
    }

cleanup:
    if (pvBuffer && 0 != dwMemSize)
    {
        DbglibLocalFree(pvBuffer);
        pvBuffer = NULL;
    }
    return dwStatus;
}

//++----------------------------------------------------------------------
//  NAME:  WebcliQueryAndCheck
//
//  DESC:  calls the required QueryContextAttributes and verifies against
//         expected results.
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
WebcliQueryAndCheck(
    IN     PCtxtHandle phContext)
{
    DWORD  dwStatus = SEC_E_OK;
    DWORD  dwAttr = 0;
    DWORD  dwExpected = 0;
    DWORD  dwCheckAttribute = 0;

    if (g_fQueryAndCheckReconnect)
    {
        dwAttr = SECPKG_ATTR_SESSION_INFO;
        dwExpected = g_dwReconnect;
        dwCheckAttribute = SECPKG_ATTR_SESSION_INFO_FLAG;
        dwStatus = QueryAndCheckContextWrapper(
            dwAttr,
            phContext,
            dwCheckAttribute,
            dwExpected);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fQueryAndCheckMachineId)
    {
        dwAttr = SECPKG_ATTR_SESSION_INFO;
        dwExpected = g_dwMachineID;
        dwCheckAttribute = SECPKG_ATTR_SESSION_INFO_MACHINEID;
        dwStatus = QueryAndCheckContextWrapper(
            dwAttr,
            phContext,
            dwCheckAttribute,
            dwExpected);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }
    if (g_fQueryAndCheckCiphersuite)
    {
        dwAttr = SECPKG_ATTR_CIPHER_INFO;
        dwExpected = g_dwCipherSuite;
        dwCheckAttribute = SECPKG_ATTR_CIPHER_INFO_CIPHERSUITE;
        dwStatus = QueryAndCheckContextWrapper(
            dwAttr,
            phContext,
            dwCheckAttribute,
            dwExpected);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    if (g_fQueryAndCheckKeyType)
    {
        dwAttr = SECPKG_ATTR_CIPHER_INFO;
        dwExpected = g_dwKeyType;
        dwCheckAttribute = SECPKG_ATTR_CIPHER_INFO_KEYTYPE;
        dwStatus = QueryAndCheckContextWrapper(
            dwAttr,
            phContext,
            dwCheckAttribute,
            dwExpected);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

cleanup:

    return dwStatus;
} // WebcliQueryAndCheck

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
    SchannelCred.v4.dwVersion = g_fUseSchCredentials ? SCH_CREDENTIALS_VERSION : SCHANNEL_CRED_VERSION;

    if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
    {
        // protocol
        SchannelCred.v4.grbitEnabledProtocols = g_dwProtocol;

        // Supported algorithms
        if (g_cSupportedAlgs)
        {
            SchannelCred.v4.cSupportedAlgs = g_cSupportedAlgs;
            SchannelCred.v4.palgSupportedAlgs = g_rgbSupportedAlgs;
        }

        // min cipher stength
        SchannelCred.v4.dwMinimumCipherStrength = g_dwMinCipherStrength;
        // max cipher stength
        SchannelCred.v4.dwMaximumCipherStrength = g_dwMaxCipherStrength;
    }
    else
    {
        if (SchannelCred.v5.cTlsParameters > 0)
        {
            // The last parameter in the blacklist will hold the protocol version(s) blacklisted.
            SchannelCred.v5.pTlsParameters[SchannelCred.v5.cTlsParameters - 1].grbitDisabledProtocols = g_dwDisabledProtocols;
        }
        else
        {
            if (g_dwDisabledProtocols > 0)
            {
                tlsParameters.grbitDisabledProtocols = g_dwDisabledProtocols;
                SchannelCred.v5.pTlsParameters = &tlsParameters;
                SchannelCred.v5.cTlsParameters = 1;
            }
        }
    }

    // prevent Schannel from automatically providing
    // a certificate chain for client auth
    if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
    {
        SchannelCred.v4.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    }
    else
    {
        SchannelCred.v5.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    }

    //
    // Default: Schannel automatically validates server certificate
    // If user selects manual or no server certificate validation
    // then tell Schannel not to validate server cert
    //
    if ((!g_fAutoServerCheck || g_fNoSrvCertCheck) &&
        !g_fAchReqDeferredCredValidation &&
        !g_fIscReqDeferredCredValidation)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        }
    }

    //
    // When Schannel validates server cert it compares the supplied
    // target name with subject name in server cert.
    // This can be disabled via the option  SCH_CRED_NO_SERVERNAME_CHECK
    //
    if (g_fAutoServerCheck && g_fNoSrvNameCheck)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
        }
    }

    if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
    {
        // add the revocation check option selected
        SchannelCred.v4.dwFlags |= dwSrvCertRvcnOpt;
        // enable send root flag
        SchannelCred.v4.dwFlags |= g_dwSendRootCert;
    }
    else
    {
        // add the revocation check option selected
        SchannelCred.v5.dwFlags |= dwSrvCertRvcnOpt;
        // enable send root flag
        SchannelCred.v5.dwFlags |= g_dwSendRootCert;
    }

    // if Schannel requires to send extra record
    // enable SCH_SEND_AUX_RECORD flag
    if (g_fSendExtraRecord == TRUE)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_SEND_AUX_RECORD;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_SEND_AUX_RECORD;
        }
    }

    if (g_fUseSecureCiphers)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_USE_STRONG_CRYPTO;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_USE_STRONG_CRYPTO;
        }
    }

    if (g_fAllowNullEncryptionCiphers)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
        }
    }

    if (g_fAchReqDeferredCredValidation)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
        }
    }

    //
    // call ACH
    //

    printf("- Calling user ACH for default creds\n");
    dwStatus = AcquireCredentialsHandle(
            NULL,                   // Name of principal
            g_pszTLSPackageName,    // Name of package
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

    if (g_fAllocateMemory)
    {
        dwStatus = InitPackage(&g_dwMaxToken);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

    //=======================================================================
    // Create initial default client credentials.
    //=======================================================================
    if (CLIENT_AUTH_MANUAL == dwClientAuthMode && (NULL != g_pszUserName || NULL != g_pszPfxPath))
    {
        dwStatus = CreateClientCredentials(
            g_pszUserName,
            g_pszPfxPath,
            &hClientCreds);
    }
    else
    {
        dwStatus = CreateDefaultClientCredentials(&hClientCreds);
    }
    if (SEC_E_OK != dwStatus)
    {
        goto cleanup;
    }

    //=======================================================================
    // Query requested credentials attributes
    //=======================================================================
    dwStatus = WebcliQueryCred(&hClientCreds);
    if (MYDBG_SUCCESS != dwStatus)
    {
        goto cleanup;
    }

    //=======================================================================
    // Connect to server.
    //=======================================================================
    if (fUseSockets)
    {
        if (dwStatus = ConnectToServer(g_pszServerName, iPortNumber, &Socket))
        {
            printf("- Error connecting to server!\n");
            goto cleanup;
        }
    }

    printf("- Connected to %s on port: %d.\n", g_pszServerName, iPortNumber);

    //=======================================================================
    // Perform handshake
    //=======================================================================
    dwStatus = PerformClientHandshake(
        Socket,
        &hClientCreds,
        g_pszTargetName,
        &hContext,
        &ExtraData,
        &quicApplicationKeys);
    if (MYDBG_SUCCESS != dwStatus)
    {
        if (g_dwExpectedISCError == dwStatus)
        {
            printf("- PerformClientHandshake was expected to fail here and it did.\n");
            dwStatus = MYDBG_SUCCESS;
        }
        goto cleanup;
    }

    printf("- HANDSHAKE WAS SUCCESSFUL.\n");

    //=======================================================================
    // Print Security Packages info if required
    //=======================================================================
    if (g_fPackageInfo)
    {
        PrintSecPkgsInfo(&hContext);
    }


    //=======================================================================
    // Manually Authenticate server's credentials
    //
    // *DeferredCredValidation is checked as part of WebcliQueryContext.
    //=======================================================================
    if (!g_fNoSrvCertCheck &&
        !g_fAutoServerCheck &&
        !g_fIscReqDeferredCredValidation &&
        !g_fAchReqDeferredCredValidation)
    {
        printf("- Manually validating server cert.\n");
        dwStatus = ManualServerCertValidation(
            g_pszTargetName,
            0,
            Socket,
            &hClientCreds,
            &hContext);
        if (SEC_E_OK != dwStatus)
        {
            printf("ManualServerCertValidation 0x%X\n", dwStatus);

            goto cleanup;
        }
    }

    //=======================================================================
    // Check Certificate Subject if requested.
    //=======================================================================
    if (NULL != g_pszSrvCertNameToVerify)
    {
        printf("- Checking server cert subject name.\n");
        dwStatus = VerifyServerCertSubjectName(&hContext);
        if (SEC_E_OK != dwStatus)
        {
            goto cleanup;
        }
    }

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
    // call SetContextAttributes wrapper to set context attributes
    //=======================================================================
    dwStatus = WebcliSetContext(
        &hContext);
    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x setting context info!\n", dwStatus);
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }

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
    // call QueryAndCheckAttributes wrapper to verify attributes
    //=======================================================================
    dwStatus = WebcliQueryAndCheck(&hContext);
    if (SEC_E_OK != dwStatus)
    {
        goto cleanup;
    }

    //=======================================================================
    // Disable reconnects for this session if requested
    // Reconnects are allowed by default
    //=======================================================================
    if (g_fDisableReconnects)
    {
        dwStatus = DisableReconnects(&hContext);
        if (dwStatus != SEC_E_OK)
        {
            printf("- Error 0x%x in disabling reconnects.\n", dwStatus);
            goto cleanup;
        }
        g_fDisableReconnects = FALSE; // to not do this multiple times
    }

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
            pszFileName,
            &quicApplicationKeys,
            &ExtraData);
        if (dwStatus == SEC_I_CONTEXT_EXPIRED && g_fAllowEarlyDisconnect)
        {
            // The server closed the connection early.
            // We expect this if we are testing early closure.
            printf("- The server sent a close_notify early!\n");
            fReceivedCloseNotify = TRUE;
            fConnectionReadClosed = TRUE;
            // Skip additional fetches and begin graceful shutdown.
            g_fKeepAlive = FALSE;
        }
        else if (dwStatus != SEC_E_OK)
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
    if (g_fKeepAlive)
    {
        for (i = 1; i < g_dwIterationCount; i++)
        {
            // print the fetch count
            printf(": Fetch count is %d", i + 1);

            //
            // Renegotiation: Request a new SSL handshake.
            //

            if (g_fRenegotiate)
            {
                printf("- Renegotiating to %s on port: %d\n", g_pszServerName, iPortNumber);

                dwStatus = InitiateRenegotiation(
                    Socket,
                    &hClientCreds,
                    g_pszTargetName,
                    &hContext);

                if (FAILED(dwStatus))
                {
                    printf("- Error 0x%x returned by InitiateRenegotiation!\n", dwStatus);
                    goto cleanup;
                }

                while (TRUE)
                {
                    // Client initiated renegotiation
                    // Read an application data packet from the server.
                    // Ideally, this should fail with SEC_I_RENEGOTIATE.
                    dwStatus = SslReadPacket(
                        Socket,
                        &hContext,
                        rgbBuffer,
                        IO_BUFFER_SIZE,
                        &cbData,
                        &pbExtra,
                        &cbExtra,
                        NULL,
                        NULL);

                    if (dwStatus == SEC_I_RENEGOTIATE)
                    {
                        printf("- SslReadPacket returned SEC_I_RENEGOTIATE.\n");
                        break;
                    }
                    else if (dwStatus != SEC_E_OK || cbData == 0)
                    {
                        printf("- Expected server renegotiation. Return is 0x%lx!\n", dwStatus);
                        dwStatus = MYDBG_ERROR_ERROR;
                        goto cleanup;
                    }

                    printf("- Discard %d bytes of data after requesting renegotiation.\n", cbData);
                    MoveMemory(rgbBuffer, pbExtra, cbExtra);
                    cbData = cbExtra;
                }

                // Finish the renegotiation handshake.
                ExtraBuffer.pvBuffer = pbExtra;
                ExtraBuffer.cbBuffer = cbExtra;

                dwStatus = ClientHandshakeLoop(
                    Socket,
                    &hClientCreds,
                    &hContext,
                    TRUE,
                    &ExtraBuffer,
                    NULL,
                    NULL);

                if (dwStatus != SEC_E_OK)
                {
                    if (rgbBuffer)
                    {
                        LocalFree(rgbBuffer);
                        rgbBuffer = NULL;
                    }
                    goto cleanup;
                }

            } 

            //
            // Reconnection Case
            //

            else if (g_fReconnect)
            {
                // close existing connection
                // and start a new one

                // if requested, send close_notify
                if (g_fSendCloseNotify)
                {
                    dwStatus = DisconnectFromServer(
                        Socket,
                        &hClientCreds,
                        &hContext,
                        &quicApplicationKeys);
                    if (FAILED(dwStatus))
                    {
                        printf("- Failed to send close_notify to server!\n");
                        goto cleanup;
                    }
                }

                // First shutdown write side of connection so we don't deadlock on
                // receiving data.
                if (fUseSockets)
                {
                    // shutdown Socket, returns 0 for success
                    if (shutdown(Socket, SD_SEND))
                    {
                        printf("- Socket shutdown failed with %d!\n", WSAGetLastError());
                        dwStatus = MYDBG_ERROR_ERROR;
                        goto cleanup;
                    }
                }
                else
                {
                    SendToServer(NULL, 0);
                }
                fConnectionWriteClosed = TRUE;

                // Drain the connection gracefully. Process whatever data remains in transit.
                dwStatus = DrainConnection(
                    Socket,
                    &hContext,
                    &hClientCreds,
                    rgbBuffer,
                    IO_BUFFER_SIZE,
                    &quicApplicationKeys,
                    TRUE,
                    &fReceivedCloseNotify);
                if (FAILED(dwStatus))
                {
                    printf("- DrainConnection failed in Reconnect scenario with %d!\n", dwStatus);
                    goto cleanup;
                }
                fConnectionReadClosed = TRUE;

                if (g_fVerifyReceiveCloseNotify && !fReceivedCloseNotify)
                {
                    printf("- Reconnect - expected but did not receive close_notify from peer.\n");
                    if (SUCCEEDED(dwStatus))
                    {
                        dwStatus = MYDBG_ERROR_ERROR;
                    }
                    goto cleanup;
                }

                if (fUseSockets)
                {
                    // Close socket.
                    if (Socket != INVALID_SOCKET)
                    {
                        printf(
                            "- Closing Socket.");
                        // shutdown Socket, returns 0 for success
                        if (shutdown(Socket, SD_BOTH))
                        {
                            printf("- Socket shutdown failed in Reconnect scenario!\n");
                            goto cleanup;
                        }
                        // close the socket, returns 0 for success
                        if (closesocket(Socket))
                        {
                            printf("- Socket close failed in Reconnect scenario!\n");
                            goto cleanup;
                        }
                        Socket = INVALID_SOCKET;
                    }
                }

                //
                // During a reconnect, the current context handle should be closed.
                // So delete the security context here.
                //

                // Free security context.
                if (hContext.dwLower || hContext.dwUpper)
                    {
                        DeleteSecurityContext(&hContext);
                    }

                //
                // Start a new Connection to the server.
                //

                if (fUseSockets)
                {
                    if (g_fReconnectToSecondServer)
                    {
                        printf( "Re-Connecting to %s on port: %d\n", g_pszSecondServerName, iPortNumber);
                        if (dwStatus = ConnectToServer(g_pszSecondServerName, iPortNumber, &Socket))
                        {
                            printf("- Error RE-CONNECTING to server\n");
                            goto cleanup;
                        }
                    }
                    else
                    {
                        printf( "Re-Connecting to %s on port: %d\n", g_pszServerName, iPortNumber);
                        if (dwStatus = ConnectToServer(g_pszServerName, iPortNumber, &Socket))
                        {
                            printf("- Error RE-CONNECTING to server\n");
                            goto cleanup;
                        }
                    }
                }
                // A new connection is now established.
                fConnectionWriteClosed = FALSE;
                fConnectionReadClosed = FALSE;
                fReceivedCloseNotify = FALSE;

                if (ExtraData.pvBuffer)
                {
                    LocalFree(ExtraData.pvBuffer);
                    ExtraData.pvBuffer = NULL;
                    ExtraData.cbBuffer = 0;
                }

                //
                // Perform handshake: reconnect should be short
                //
                ZeroMemory(&quicApplicationKeys, sizeof(quicApplicationKeys));
                if (dwStatus = PerformClientHandshake(
                    Socket,
                    &hClientCreds,
                    g_pszTargetName,
                    &hContext,
                    &ExtraData,
                    &quicApplicationKeys))
                {
                    printf("- Error performing handshake: 0x%x\n", dwStatus);
                    goto cleanup;
                }

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

                //=======================================================================
          // call QueryAndCheckAttributes wrapper to verify attributes
          //=======================================================================
                g_fQueryAndCheckReconnect = TRUE;
                dwStatus = WebcliQueryAndCheck(
                    &hContext);

                if (SEC_E_OK != dwStatus)
                {
                    printf("- Error 0x%x querying session info!\n", dwStatus);

                    goto cleanup;
                }

            } // elseif(g_fReconnect)

            //
            // Get the connection info after the reconnect.
            //

            //=======================================================================
            // Display connection info.
            //=======================================================================
            dwStatus = QueryContextWrapper(
                SECPKG_ATTR_SESSION_INFO,
                &hContext);

            if (dwStatus != SEC_E_OK)
            {
                printf("- Error 0x%x querying session info!\n", dwStatus);
                goto cleanup;
            }

            //
            // Request the file again
            // (in case of reconnection its over a new socket)
            //

            if (HttpsGetFile(Socket,
                &hClientCreds,
                &hContext,
                pszFileName,
                &quicApplicationKeys,
                &ExtraData)
                )
            {
                printf("- Error fetching file from the server\n");
                goto cleanup;
            }

        } // for("i" iterations)
    } // if(g_fKeepAlive)


    // If requested, Send close_notify before closing connection
    if (g_fSendCloseNotify)
    {
        if (INVALID_SOCKET == Socket)
        {
            printf("- SOCKET_INVALID, can't send close_notify\n");
            goto cleanup;
        }
        else
        {
            DWORD dwCloseNotifyStatus = DisconnectFromServer(
                Socket,
                &hClientCreds,
                &hContext,
                &quicApplicationKeys);
            if (FAILED(dwCloseNotifyStatus))
            {
                printf("- Failed to send close_notify to server!\n");
                dwStatus = dwCloseNotifyStatus;
                goto cleanup;
            }
        }
    }

    // First shutdown write side of connection so we don't deadlock on
    // receiving data.
    if (fUseSockets)
    {
        // shutdown Socket, returns 0 for success
        if (shutdown(Socket, SD_SEND))
        {
            printf("- Socket shutdown failed with %d!\n", WSAGetLastError());
            dwStatus = MYDBG_ERROR_ERROR;
            goto cleanup;
        }
    }
    else
    {
        SendToServer(NULL, 0);
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

    if (g_fVerifyReceiveCloseNotify && !fReceivedCloseNotify)
    {
        printf("- Expected but did not receive close_notify from peer.\n");
        if (SUCCEEDED(dwStatus))
        {
            dwStatus = MYDBG_ERROR_ERROR;
        }
    }
    else if (g_fVerifyReceiveCloseNotify && dwStatus == SEC_I_CONTEXT_EXPIRED)
    {
        // If we are asked to verify that we receive a close notify and receive one, the test
        // is considered passing.
        dwStatus = SEC_E_OK;
    }

    if (g_fEncryptAfterPostHandshake)
    {
        // If we never got SEC_I_RENEGOTIATE, we were unable to test the condition so the test failed
        printf("- EncryptAfterPostHandshake specified but SEC_I_RENEGOTIATE never happened 0x%X\n", dwStatus);
        if (SUCCEEDED(dwStatus))
        {
            dwStatus = MYDBG_ERROR_ERROR;
        }
    }

cleanup:

    if (!fConnectionWriteClosed)
    {
        if (fUseSockets)
        {
            if (shutdown(Socket, SD_SEND))
            {
                printf("- Socket shutdown failed with %d!\n", WSAGetLastError());
            }
        }
        else
        {
            SendToServer(NULL, 0);
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

    if (0 != g_hProv)
    {
        CryptReleaseContext(g_hProv, 0);
    }
    if (NULL != g_pDupCertContext)
    {
        CertFreeCertificateContext(g_pDupCertContext);
        g_pDupCertContext = NULL;
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

//++----------------------------------------------------------------------
//  NAME:  SetFalsStart
//
//  DESC:  Calls SetContextAttributes to set secpkg_attr_false_start attribute
//
//  ARGUMENTS:
//  - PCtxtHandle				: context handle
//
//  RETURNS:
//  - DWORD: status code
//
//  NOTE:
//--------------------------------------------------------------------++//
DWORD
SetEarlyStart(
    IN     PCtxtHandle phContext)
{

    DWORD                       dwStatus = MYDBG_ERROR_ERROR;
    PSecPkgContext_EarlyStart   pEarlyStart = NULL;
    ULONG                       dwMemSize = 0;
    DWORD                       dwFSflag = 0;

    dwMemSize = sizeof(SecPkgContext_EarlyStart);
    pEarlyStart = (PSecPkgContext_EarlyStart)DbglibLocalAlloc(dwMemSize);
    if (pEarlyStart == NULL)
    {
        dwStatus = MYDBG_ERROR_OUTOFMEMORY;
        goto cleanup;
    }

    if (g_fSetTlsClientEarlyStart)
    {
        dwFSflag |= ENABLE_TLS_CLIENT_EARLY_START;
    }

    pEarlyStart->dwEarlyStartFlags = dwFSflag;
    printf("- dwEarlyStartFlags is: %ld\n", pEarlyStart->dwEarlyStartFlags);
    dwStatus = SetContextAttributes(phContext,
        SECPKG_ATTR_EARLY_START,
        pEarlyStart,
        dwMemSize);

    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x Setting Early Start Attribute!\n", dwStatus);
        //PrintSecurityError(dwStatus);
    }

cleanup:
    if (pEarlyStart)
    {
        DbglibLocalFree(pEarlyStart);
    }

    return dwStatus;
}

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

    if (g_fAllocateMemory)
    {

        if (g_fUseSmallBuffer)
        {
            // TODO: Handle small buffer scenario on initial ISC call.
            cbToken = g_dwMaxToken;
        }
        else
        {
            cbToken = g_dwMaxToken;
        }
        pbToken = (PBYTE)DbglibLocalAlloc(cbToken);
        if (NULL == pbToken)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
            goto error;
        }

        pbAlert = (PBYTE)DbglibLocalAlloc(g_dwMaxToken);
        if (NULL == pbAlert)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
            goto error;
        }
        cbAlert = g_dwMaxToken;
    }

    if (g_fNoRecordLayer)
    {
        reqExtendedFlags.Flags |= ISC_REQ_MESSAGES;
    }

    if (g_fIscReqDeferredCredValidation)
    {
        reqExtendedFlags.Flags |= ISC_REQ_DEFERRED_CRED_VALIDATION;
    }

    if (g_fNoPostHandshakeAuth)
    {
        reqExtendedFlags.Flags |= ISC_REQ_NO_POST_HANDSHAKE_AUTH;
    }

    if (reqExtendedFlags.Flags > 0)
    {
        InBuffers[dwInBufferNum].pvBuffer = &reqExtendedFlags;
        InBuffers[dwInBufferNum].cbBuffer = sizeof(reqExtendedFlags);
        InBuffers[dwInBufferNum].BufferType = SECBUFFER_FLAGS;
        dwInBufferNum++;
    }

    if (g_dwGeExtensionType <= USHRT_MAX && g_dwGeHandshakeType <= UCHAR_MAX)
    {
        if (g_pszGeContents != NULL)
        {
            dwGeContents = strlen(g_pszGeContents) + sizeof(BYTE);
        }

        DWORD cbBuffer = max(sizeof(SEND_GENERIC_TLS_EXTENSION), FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer) + dwGeContents);

        pSendGenericTlsExtension = (PSEND_GENERIC_TLS_EXTENSION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer);

        if (pSendGenericTlsExtension == NULL)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }

        pSendGenericTlsExtension->ExtensionType = g_dwGeExtensionType;
        pSendGenericTlsExtension->HandshakeType = g_dwGeHandshakeType;
        pSendGenericTlsExtension->BufferSize = dwGeContents;

        if (dwGeContents > 0)
        {
            RtlCopyMemory(pSendGenericTlsExtension->Buffer, g_pszGeContents, dwGeContents);
        }

        InBuffers[dwInBufferNum].pvBuffer = pSendGenericTlsExtension;
        InBuffers[dwInBufferNum].cbBuffer = cbBuffer;
        InBuffers[dwInBufferNum].BufferType = SECBUFFER_SEND_GENERIC_TLS_EXTENSION;
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
        OutBuffers[dwOutBufferNum].cbBuffer = g_fAllocateMemory ? sizeof(retExtendedFlags) : 0;
        OutBuffers[dwOutBufferNum].pvBuffer = g_fAllocateMemory ? &retExtendedFlags : NULL;
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
        (g_fAllocateMemory ? 0 : ISC_REQ_ALLOCATE_MEMORY) |
        (g_fConnectionMode ? ISC_REQ_CONNECTION : ISC_REQ_STREAM);

    if (g_fMutualAuth)
    {
        dwSSPIFlags |= ISC_REQ_MUTUAL_AUTH;
    }

    if (g_fManualCredValidation)
    {
        dwSSPIFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;
    }

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

            if (g_fNoRecordLayer && (retExtendedFlags.Flags & ISC_RET_MESSAGES) == 0)
            {
                dwStatus = WEBCLI_ERROR_ERROR;
                goto error;
            }
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

            if (g_fNoRecordLayer)
            {
                OutBuffers[0].pvBuffer = DbglibLocalAlloc(OutBuffers[0].cbBuffer + TLS_RECORD_HEADER);

                if (NULL == OutBuffers[0].pvBuffer)
                {
                    dwStatus = ERROR_NOT_ENOUGH_MEMORY;
                    printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
                    goto error;
                }

                PBYTE pTokenBuffer = (PBYTE)OutBuffers[0].pvBuffer;
                OutBuffers[0].cbBuffer += TLS_RECORD_HEADER;

                *pTokenBuffer++ = HANDSHAKE_TRAFFIC;
                *pTokenBuffer++ = MSBOF(cbSendToServer);
                *pTokenBuffer++ = LSBOF(cbSendToServer);

                RtlCopyMemory(pTokenBuffer, pbSendToServer, cbSendToServer);
                DbglibLocalFree(pbSendToServer);
                pbSendToServer = (PBYTE)OutBuffers[0].pvBuffer;
                cbSendToServer = OutBuffers[0].cbBuffer;
            }
        }
        else if (OutBuffers[1].cbBuffer != 0 &&
            OutBuffers[1].pvBuffer != NULL)
        {
            pbSendToServer = (PBYTE)OutBuffers[1].pvBuffer;
            cbSendToServer = OutBuffers[1].cbBuffer;
        }
    
    if (cbSendToServer != 0 && pbSendToServer != NULL)
    {
        if ((g_dwProtocol & SP_PROT_SSL2) && g_fDowngrade)
        {
            *(pbSendToServer + 3) = 0x0;
            *(pbSendToServer + 4) = 0x2;
        }

        if (fUseSockets)
        {
            cbData = send(
                Socket,
                (LPCSTR)pbSendToServer,
                cbSendToServer,
                0);
            g_dwNumServerSends++;
        }
        else
        {
            cbData = SendToServer((LPSTR)pbSendToServer, cbSendToServer);
        }

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

    // request for early (false) start
    if (g_fEarlyStartRequested && !g_fEarlyStartReady)
    {
        dwStatus = SetEarlyStart(phContext);
        if (SEC_E_OK == dwStatus)
        {
            printf("- EarlyStart SetContextAttribute Succeeded! 0x%X\n", dwStatus);
        }
        else
        {
            printf("- EarlyStart SetContextAttribute FAILED to set SECPKG_ATTR_EARLY_START!\n");

            goto error;
        }
    }

    if (g_fQryCtxtCertValidationResult)
    {
        // Check that querying before receiving server cert returns correct code
        dwStatus = QueryContextWrapper(
            SECPKG_ATTR_CERT_CHECK_RESULT,
            phContext);
        if (dwStatus != SEC_E_NO_CREDENTIALS)
        {
            printf("- QCA(SECPKG_ATTR_CERT_CHECK_RESULT) expected to return SEC_E_NO_CREDENTIALS when querying too early, actual return: 0x%x\n",
                dwStatus);
            goto error;
        }
    }
    if (g_fQryCtxtSerializedRemoteCert)
    {
        PCCERT_CONTEXT pCert = NULL;
        HRESULT hrQueryStatus = QueryAndDeserializeRemoteCertContext(
            FALSE ? ClientContext : phContext,
            TRUE,
            &pCert);
        if (hrQueryStatus != SEC_E_NO_CREDENTIALS)
        {
            printf("- QCA(SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT) expected to return SEC_E_NO_CREDENTIALS when querying too early, actual return: 0x%x\n",
                hrQueryStatus);
            if (SUCCEEDED(hrQueryStatus))
            {
                CertFreeCertificateContext(pCert);
                dwStatus = MYDBG_ERROR_ERROR;
            }
            else
            {
                dwStatus = (DWORD)hrQueryStatus;
            }
            goto error;
        }
    }

    dwStatus = ClientHandshakeLoop(
        Socket,
        phCreds,
        phContext,
        TRUE,
        pExtraData,
        &quicHandshakeKeys,
        pQuicApplicationKeys);

    // check if early (false) start happened
    if (g_fEarlyStartRequested && !g_fEarlyStartReady)
    {
        printf("- EarlyStart ISC FAILED (didn't return SEC_I_CONTINUE_NEEDED_MESSAGE_OK)!\n");

        // mark the test for failure
        dwStatus = WEBCLI_ERROR_ERROR;

        goto error;
    }

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
        if (!g_fAllocateMemory)
        {
            FreeOutputBuffer(pRetFlagsBuffer);
        }
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
        (g_fAllocateMemory ? 0 : ISC_REQ_ALLOCATE_MEMORY) |
        (g_fConnectionMode ? ISC_REQ_CONNECTION : ISC_REQ_STREAM);

    if (g_fMutualAuth)
    {
        dwSSPIFlags |= ISC_REQ_MUTUAL_AUTH;
    }

    if (g_fNoRecordLayer)
    {
        reqExtendedFlags.Flags |= ISC_REQ_MESSAGES;
    }

    if (g_fIscReqDeferredCredValidation)
    {
        reqExtendedFlags.Flags |= ISC_REQ_DEFERRED_CRED_VALIDATION;
    }

    if (g_fNoPostHandshakeAuth)
    {
        reqExtendedFlags.Flags |= ISC_REQ_NO_POST_HANDSHAKE_AUTH;
    }

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

    if (g_dwGeExtensionType <= USHRT_MAX && g_dwGeHandshakeType <= UCHAR_MAX && !fIsPosthandshakeMessage)
    {
        if (g_pszGeContents != NULL)
        {
            dwGeContents = strlen(g_pszGeContents) + sizeof(BYTE);
        }

        cbSendGenericTlsExtension = max(sizeof(SEND_GENERIC_TLS_EXTENSION), FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer) + dwGeContents);

        pSendGenericTlsExtension = (PSEND_GENERIC_TLS_EXTENSION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSendGenericTlsExtension);
        if (pSendGenericTlsExtension == NULL)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }
    }

    if (g_dwGeExtensionTypeVerify <= USHRT_MAX && g_dwGeHandshakeTypeVerify <= UCHAR_MAX && !fIsPosthandshakeMessage)
    {
        cbSubscribeGenericTlsExtension = sizeof(SUBSCRIBE_GENERIC_TLS_EXTENSION);

        pSubscribeGenericTlsExtension = (PSUBSCRIBE_GENERIC_TLS_EXTENSION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSubscribeGenericTlsExtension);

        if (pSubscribeGenericTlsExtension == NULL)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }
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
                if (fUseSockets)
                {
                    cbData = recv(
                        Socket,
                        (LPSTR)(IoBuffer + cbIoBuffer),
                        min(g_IoBufSize, IO_BUFFER_SIZE - cbIoBuffer),
                        0);
                }
                else
                {
                    cbData = ReceiveFromServer((LPSTR)IoBuffer + cbIoBuffer,
                        min(g_IoBufSize, IO_BUFFER_SIZE - cbIoBuffer));
                }

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

        if (g_dwGeExtensionType <= USHRT_MAX && g_dwGeHandshakeType <= UCHAR_MAX && !fIsPosthandshakeMessage)
        {
            RtlZeroMemory(pSendGenericTlsExtension, cbSendGenericTlsExtension);
            pSendGenericTlsExtension->ExtensionType = g_dwGeExtensionType;
            pSendGenericTlsExtension->HandshakeType = g_dwGeHandshakeType;
            pSendGenericTlsExtension->BufferSize = dwGeContents;

            if (dwGeContents > 0)
            {
                RtlCopyMemory(pSendGenericTlsExtension->Buffer, g_pszGeContents, dwGeContents);
            }

            InBuffers[dwInBufferNum].pvBuffer = pSendGenericTlsExtension;
            InBuffers[dwInBufferNum].cbBuffer = cbSendGenericTlsExtension;
            InBuffers[dwInBufferNum].BufferType = SECBUFFER_SEND_GENERIC_TLS_EXTENSION;
            dwInBufferNum++;
        }

        if (g_dwGeExtensionTypeVerify <= USHRT_MAX && g_dwGeHandshakeTypeVerify <= USHRT_MAX && !fIsPosthandshakeMessage)
        {
            RtlZeroMemory(pSubscribeGenericTlsExtension, cbSubscribeGenericTlsExtension);

            TLS_EXTENSION_SUBSCRIPTION extension = { (WORD)g_dwGeExtensionTypeVerify, (WORD)g_dwGeHandshakeTypeVerify };

            RtlCopyMemory(pSubscribeGenericTlsExtension->Subscriptions, &extension, sizeof(extension));
            pSubscribeGenericTlsExtension->SubscriptionsCount = 1;

            InBuffers[dwInBufferNum].pvBuffer = pSubscribeGenericTlsExtension;
            InBuffers[dwInBufferNum].cbBuffer = cbSubscribeGenericTlsExtension;
            InBuffers[dwInBufferNum].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
            dwInBufferNum++;
        }

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
        dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], g_fAllocateMemory, g_fUseSmallBuffer, g_dwMaxToken);
        if (dwStatus != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_TOKEN;
        dwOutBufferNum++;

        // Alert buffer
        dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], g_fAllocateMemory, g_fUseSmallBuffer, g_dwMaxToken);
        if (dwStatus != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_ALERT;
        dwOutBufferNum++;

        // Generic extensions buffer
        if (g_dwGeExtensionTypeVerify <= USHRT_MAX && g_dwGeHandshakeTypeVerify <= UCHAR_MAX && !fIsPosthandshakeMessage)
        {
            dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], g_fAllocateMemory, g_fUseSmallBuffer, 100);
            if (dwStatus != ERROR_SUCCESS)
            {
                goto cleanup;
            }

            OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
            pSubscribeBuffer = &OutBuffers[dwOutBufferNum];
            dwOutBufferNum++;
        }

        // Context returned flags buffer
        if (reqExtendedFlags.Flags > 0)
        {
            dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], g_fAllocateMemory, g_fUseSmallBuffer, sizeof(SEC_FLAGS));
            if (dwStatus != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_FLAGS;
            pRetFlagsBuffer = &OutBuffers[dwOutBufferNum];
            dwOutBufferNum++;
        }

        // Traffic secrets buffers
        for (int i = 0; g_fNoRecordLayer && i < COUNT_OF_TRAFFIC_SECRETS; i++)
        {
            dwStatus = AllocateOutputBuffer(&OutBuffers[dwOutBufferNum], g_fAllocateMemory, g_fUseSmallBuffer, TRAFFIC_SECRET_MAX_SIZE);
            if (dwStatus != ERROR_SUCCESS)
            {
                goto cleanup;
            }
            OutBuffers[dwOutBufferNum].BufferType = SECBUFFER_TRAFFIC_SECRETS;
            pTrafficSecrets[i] = &OutBuffers[dwOutBufferNum];
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

            if (g_fNoRecordLayer && (pRetExtendedFlags->Flags & ISC_RET_MESSAGES) == 0)
            {
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }

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

        // If we are asked to check result during handshake, do it now.
        // Once we get it, stop.
        if (g_fQryCtxtCertValidationResult && !fQryCertValidationResultReceivedServerCert)
        {
            // Check that querying before receiving server cert returns correct code
            DWORD dwQueryStatus = QueryContextWrapper(
                SECPKG_ATTR_CERT_CHECK_RESULT,
                phContext);
            if (dwQueryStatus == SEC_E_NO_CREDENTIALS)
            {
                // Ignore and proceed
            }
            else if (dwQueryStatus == MYDBG_ERROR_BADPARAMETER)
            {
                // Received a cert but error bits set
                fQryCertValidationResultReceivedServerCert = TRUE;
            }
            else if (dwQueryStatus == SEC_E_OK)
            {
                // Received a good cert
                fQryCertValidationResultReceivedServerCert = TRUE;
                fQryCertValidationResultIsServerCertValid = TRUE;
            }
            else
            {
                printf("- QCA SECPKG_ATTR_CERT_CHECK_RESULT returned unexpected error, terminating!\n");
                //PrintSecurityError(dwQueryStatus);
                dwStatus = dwQueryStatus;
                goto cleanup;
            }
        }
        if (g_fQryCtxtSerializedRemoteCert && !fQrySerializedRemoteCertComplete)
        {
            PCCERT_CONTEXT pCert = NULL;
            HRESULT hrQueryStatus = QueryAndDeserializeRemoteCertContext(
                ClientContext ,
                TRUE,
                &pCert);

            if (SUCCEEDED(hrQueryStatus))
            {
                fQrySerializedRemoteCertComplete = TRUE;
                CertFreeCertificateContext(pCert);
            }
            else if (hrQueryStatus != SEC_E_NO_CREDENTIALS)
            {
                printf("- QCA(SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT) failed!: 0x%x\n", hrQueryStatus);
                dwStatus = (DWORD)hrQueryStatus;
                goto cleanup;
            }
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
                if (fUseSockets)
                {
                    cbData = send(
                        Socket,
                        (LPCSTR)OutBuffers[0].pvBuffer,
                        OutBuffers[0].cbBuffer,
                        0);
                    g_dwNumServerSends++;
                }
                else
                {
                    cbData = SendToServer((LPSTR)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
                }

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
                if (!g_fEarlyStartRequested)
                {
                    printf("- EarlyStart not requested. SEC_I_CONTINUE_NEEDED_MESSAGE_OK seen.\n");
                }

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
                    pszFileName,
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
            if (g_CheckFlagExtendedError)
            {
                printf(" Context Flags in: 0x%x\n", dwSSPIFlags);
                printf(" Context Flags out : 0x%x\n\t", dwSSPIOutFlags);

                // If ISC_REQ_EXTENDED_ERROR flag is set
                // Schannel should set ISC_RET_EXTENDED_ERROR flag (KB975858)
                if (0 != (dwSSPIFlags & ISC_REQ_EXTENDED_ERROR))
                {
                    if (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
                    {
                        printf(" Success in EXTENDED_EROR flag case\n");
                    }
                    else
                    {
                        printf(" Failure in EXTENDED_EROR flag case\n");
                        dwStatus = SEC_E_INTERNAL_ERROR;
                        goto cleanup;
                    }
                }
            }

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
        if (dwStatus == SEC_E_OK && g_fQryCtxtIssrListEx)
        {
            // We want to fail if issuer list does not verify per
            // any of vfTrustedIssuers* is set.
            // DisplayAndVerifyIssuerListEx will check this.
            DWORD dwIssuerStatus = QueryContextWrapper(SECPKG_ATTR_ISSUER_LIST_EX, phContext);
            if (SEC_E_OK != dwIssuerStatus)
            {
                printf("- Error querying SECPKG_ISSUER_LIST_EX\n");
                dwStatus = dwIssuerStatus;
            }
            printf("- QContextA(ISSUER_LIST_EX) succeeded\n");
            // Mark done so we don't try again after the handshake completes.
            g_fQryCtxtIssrListEx = FALSE;
        }

        //
        // If InitializeSecurityContext returned
        // SEC_I_INCOMPLETE_CREDENTIALS, then the server just
        // requested client authentication.
        //

        if (dwStatus == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            printf("- ISC ret SEC_I_INCOMPLETE_CREDENTIALS, CliAuth required.\n");

            if (g_fPrecheckSrvCert)
            {
                if (SEC_E_OK != QueryContextAttributes(
                    phContext,
                    SECPKG_ATTR_REMOTE_CERT_CHAIN,
                    (PVOID)&pRemoteCert)
                    )
                {
                    printf("- Error querying SECPKG_ATTR_REMOTE_CERT_CHAIN\n");
                }
                printf("- QContextA(SECPKG_ATTR_REMOTE_CERT_CHAIN) succeeded\n");
                if (!g_fWinVerifyTrust)
                {
                    // Use CertGetCertificateChain
                    dwStatus = VerifyServerCertificate(
                        pRemoteCert,
                        g_pszTargetName,
                        0);
                }
                else
                {
                    // Use WinVerifyTrust
                    dwStatus = VerifyServerCertificateWVT(
                        pRemoteCert,
                        g_pszTargetName,
                        0);
                }

                // check if server cert validation was successful
                if (SEC_E_OK != dwStatus)
                {
                    if (!g_fCheckOcsp)
                    {
                        printf("- Error prevalidating server cert\n");
                        if (g_fSendAlert)
                        {
                            dwStatus = BuildAndSendAlert(
                                Socket,
                                phCreds,
                                phContext,
                                dwStatus);
                            if (SEC_E_OK != dwStatus)
                            {
                                printf("- Error sending alert! (0x%x)\n", dwStatus);
                            }
                        }
                        break;
                    }
                    else
                    {
                        //we WANT to fail if validation fails for OCSP
                        printf("- Error validating server cert manually - Required for OCSP\n");
                        dwStatus = MYDBG_ERROR_ERROR;
                        break;
                    }
                }
                else
                {
                    printf( "- Server Cert Chain successfully pre-verified\n");
                }
            }

            //=============================================================
            // Create NEW client creds based on options
            //=============================================================

            // marshall client credentials
            if (dwClientAuthMode == CLIENT_AUTH_PROGRAMMATIC)
            {
                dwCredStatus = ProgrammaticClientCredentials(
                    &hLocalCreds,
                    phContext);
                if (MYDBG_SUCCESS != dwCredStatus)
                {
                    printf("- Error creating credentials\n");
                    break;
                }
                printf("- webcli picked client cert programmatically.\n");
                phCreds = &hLocalCreds;
            }
            else if (dwClientAuthMode == CLIENT_AUTH_NO_CERT)
            {
                printf("- webcli will not supply a certificate.\n");
            }
            else
            {
                // We'll come here if server requests client auth but we didn't 
                // supply it earlier.
                dwCredStatus = CreateClientCredentials(
                    g_pszUserName,
                    g_pszPfxPath,
                    &hLocalCreds);
                if (MYDBG_SUCCESS != dwCredStatus)
                {
                    printf("- Error creating credentials!\n");
                    break;
                }
                phCreds = &hLocalCreds;
            }

            // Query requested credentials attributes AGAIN
            if (SEC_E_OK != WebcliQueryCred(phCreds))
            {
                goto cleanup;
            }

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
            if (!g_fNoRecordLayer)
            {
                printf("- Extra data from ISC call. Moving and looping.\n");
                MoveMemory(IoBuffer,
                    IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                    InBuffers[1].cbBuffer);
                cbIoBuffer = InBuffers[1].cbBuffer;
            }
        }
        else
        {
            cbIoBuffer = 0;
        }
    } // while(...)

    // Error out if we never received the certificate error bits or if the certificate
    // did not validate. This is for negative test cases. 
    if (g_fQryCtxtCertValidationResult && !fQryCertValidationResultIsServerCertValid)
    {
        if (!fQryCertValidationResultReceivedServerCert)
        {
            // QCA for CertValidationResult indicated we never received a certificate.
            printf("- Unable to query server cert validation bits as we never received a certificate.\n");
        }
        else
        {
            // QCA for CertValidationResult went through but the cert was invalid.
            printf("- We received a server cert but it was invalid.\n");
        }
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }

    if (g_fQryCtxtSerializedRemoteCert && !fQrySerializedRemoteCertComplete)
    {
        printf("- SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT - No server certificate was received by the end of the handshake.\n");
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }

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

    if (g_dwGeExtensionTypeVerify != ULONG_MAX &&
        g_dwGeHandshakeTypeVerify != ULONG_MAX)
    {
        if (!fReceivedGenericExtension &&
            !fIsPosthandshakeMessage)
        {
            dwStatus = WEBCLI_ERROR_ERROR;
        }

        FreeOutputBuffer(pSubscribeBuffer);
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

/*********************************************************************
 Kicks-off client initiated renegotiation
 Basically generates a client_hello and sends it across
 Not supported in kernel mode for previous to Longhorn
*********************************************************************/
unsigned long
InitiateRenegotiation(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN     LPSTR           pszServerName,
    IN     CtxtHandle* phContext)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    SecBufferDesc   InBuffer = { 0 };
    SecBuffer       InBuffers[2] = { 0 };
    SecBufferDesc   OutBuffer = { 0 };
    SecBuffer       OutBuffers[2] = { 0 };
    DWORD           dwSSPIFlags = 0;
    DWORD           dwSSPIOutFlags = 0;
    TimeStamp       tsExpiry = { 0 };
    DWORD           cbData = 0;
    PBYTE           pbToken = NULL;
    DWORD           cbToken = 0;
    PBYTE           pbAlert = NULL;
    DWORD           cbAlert = 0;
    PBYTE           pbSendToServer = NULL;
    DWORD           cbSendToServer = 0;
    DWORD           dwBuffer = 0;

    // set input flags to ISC
    dwSSPIFlags =
        ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        (g_fAllocateMemory ? 0 : ISC_REQ_ALLOCATE_MEMORY) |
        ISC_REQ_STREAM;

    if (g_fMutualAuth)
    {
        dwSSPIFlags |= ISC_REQ_MUTUAL_AUTH;
    }

    //
    //  Initiate a ClientHello message and generate a token.
    //

    if (g_fAllocateMemory)
    {
        pbToken = (PBYTE)DbglibLocalAlloc(g_dwMaxToken);
        if (NULL == pbToken)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
            goto cleanup;
        }
        cbToken = g_dwMaxToken;

        pbAlert = (PBYTE)DbglibLocalAlloc(g_dwMaxToken);
        if (NULL == pbAlert)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
            goto cleanup;
        }
        cbAlert = g_dwMaxToken;

    }

    OutBuffers[0].pvBuffer = pbToken;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = cbToken;

    OutBuffers[1].pvBuffer = pbAlert;
    OutBuffers[1].BufferType = SECBUFFER_ALERT;
    OutBuffers[1].cbBuffer = cbAlert;

    OutBuffer.cBuffers = 2;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    dwStatus = InitializeSecurityContextA(
            phCreds,
            phContext,
            pszServerName,
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            NULL,
            0,
            NULL,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

    printf("- ISC returned 0x%lx\n", dwStatus);

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
        // send client_hello to initiate renegotiation
        if (fUseSockets)
        {
            cbData = send(
                Socket,
                (LPSTR)pbSendToServer,
                cbSendToServer,
                0);
            g_dwNumServerSends++;
        }
        else
        {
            cbData = SendToServer((LPSTR)pbSendToServer, cbSendToServer);

        }

        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            dwStatus = GetLastError();
            printf("- Error %d sending data to server!\n", dwStatus);
            goto cleanup;
        }

        printf("- %d bytes of handshake data sent.\n", cbData);
        printf("- Sent handshake data buffer:\n");
        PrintHexDump(cbData, pbSendToServer);
    }

    if (dwStatus != SEC_I_CONTINUE_NEEDED)
    {
        printf("- Error 0x%x returned by InitializeSecurityContext!\n", dwStatus);
        goto cleanup;
    }

cleanup:

    // Free output buffer.
    for (dwBuffer = 0; dwBuffer < OutBuffer.cBuffers; dwBuffer++)
    {
        FreeOutputBuffer(&OutBuffers[dwBuffer]);
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
            if (fUseSockets)
            {
                DWORD cbRemainingBuffer = min(g_IoBufSize, cbBuffer - cbDataRead);
                // For connection mode we only want to read one record at a time.
                DWORD cbTempBuffer = g_fConnectionMode ? TLS_RECORD_HEADER :
                    cbRemainingBuffer;

                PBYTE pbTempBuffer = pbBuffer + cbDataRead;
                cbData = recv(
                    Socket,
                    (LPSTR)pbTempBuffer,
                    cbTempBuffer,
                    0);

                if (g_fConnectionMode &&
                    cbData == TLS_RECORD_HEADER &&
                    cbRemainingBuffer > TLS_RECORD_HEADER)
                {
                    // Find length of record;
                    cbTempBuffer = COMBINETWOBYTES(pbTempBuffer[3], pbTempBuffer[4]);
                    pbTempBuffer += TLS_RECORD_HEADER;
                    cbRemainingBuffer -= TLS_RECORD_HEADER;

                    if (cbTempBuffer > 0 &&
                        cbTempBuffer <= cbRemainingBuffer)
                    {
                        DWORD cbTempData = recv(
                            Socket,
                            (LPSTR)pbTempBuffer,
                            cbTempBuffer,
                            0);
                        if (cbTempData == SOCKET_ERROR)
                        {
                            cbData = cbTempData;
                        }
                        else
                        {
                            cbData += cbTempData;
                        }
                    }
                }
            }
            else
            {
                cbData = ReceiveFromServer((LPSTR)(pbBuffer + cbDataRead),
                    min(g_IoBufSize, cbBuffer - cbDataRead));
            }

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

        if (!g_fConnectionMode || g_fNoRecordLayer)
        { // stream mode
            Buffers[0].BufferType = SECBUFFER_DATA;
            Buffers[0].pvBuffer = pbBuffer;
            Buffers[0].cbBuffer = cbDataRead;

            Buffers[1].BufferType = SECBUFFER_EMPTY;
            Buffers[2].BufferType = SECBUFFER_EMPTY;
        }
        else
        { // connection mode
            Buffers[0].BufferType = SECBUFFER_DATA;
            Buffers[0].pvBuffer = pbBuffer;
            Buffers[0].cbBuffer = cbDataRead -
                pvSizesConnection.cbSecurityTrailer;

            Buffers[1].BufferType = SECBUFFER_TOKEN;
            Buffers[1].cbBuffer = pvSizesConnection.cbSecurityTrailer;
            Buffers[1].pvBuffer = pbBuffer + cbDataRead -
                pvSizesConnection.cbSecurityTrailer;

            Buffers[2].BufferType = SECBUFFER_EMPTY;
        }

        //
        // We need 3 empty buffers passed in for stream mode for
        // header, trailer and extra buffers.
        //

        Buffers[3].BufferType = SECBUFFER_EMPTY;
        Buffers[4].BufferType = SECBUFFER_ALERT;
        Buffers[4].cbBuffer = 255;
        Buffers[4].pvBuffer = rgbAlert;

        if (g_fMeasureAlertRespTime)
        {
            if (!QueryPerformanceFrequency(&g_sHighResolutionFrequency))
            {
                printf("- High resolution timers not supported.\n");
                return MYDBG_ERROR_ERROR;
            }
            // take time-stamp before calling decryption
            if (!QueryPerformanceCounter(&sPerformanceCountBegin))
            {
                printf("- QueryPerformanceCounter FAILED.\n");
                return MYDBG_ERROR_ERROR;
            }
        }

        // Decrypt Data
        if (g_fNoRecordLayer &&
            pQuicApplicationKeys != NULL &&
            pQuicApplicationKeys->hClientWriteKey != NULL)
        {
            dwStatus = QuicDecrypt(
                pQuicApplicationKeys,
                FALSE,
                &Buffers[0]);
            if (dwStatus == SEC_I_RENEGOTIATE)
            {
                // This will only handle a single record but will suffice for our purpose.
                cbDataRead = Buffers[0].cbBuffer;
                Buffers[1].BufferType = SECBUFFER_EXTRA;
                Buffers[1].pvBuffer = Buffers[0].pvBuffer;
                Buffers[1].cbBuffer = Buffers[0].cbBuffer;
                Buffers[0].cbBuffer = 0;
                Buffers[0].pvBuffer = NULL;
            }
        }
        else
        {
            dwStatus = DecryptMessage(
                phContext,
                &Message,
                0,
                NULL);
        }

        if (g_fMeasureAlertRespTime)
        {
            // take time-stamp after decryption
            if (!QueryPerformanceCounter(&sPerformanceCountEnd))
            {
                printf("- QueryPerformanceCounter FAILED.\n");
                return MYDBG_ERROR_ERROR;
            }
        }

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

                if (g_fMeasureAlertRespTime)
                {
                    // compute elapsed time from decryption
                    sCountElapsed.QuadPart =
                        sPerformanceCountEnd.QuadPart - sPerformanceCountBegin.QuadPart;
                    printf("- Decryption Time: %.6Lf millisecs\n", sCountElapsed.QuadPart * 1000.0
                        / g_sHighResolutionFrequency.QuadPart);
                }
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

                // Check if last data buffer contained only 1 byte
                if (g_fVerifyExtraRecord == TRUE)
                {
                    if (pDataBuffer->cbBuffer == 1)
                    {
                        g_fExtraDataReceived = TRUE;
                        printf("- PASS: Extra record of 1 byte received successfully from server\n");
                    }
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

    if (g_fNonContiguousBuffers)
    {
        if (!g_fConnectionMode)
        {
            cbHeader = pvSizesStream.cbHeader;
            pbHeader = (PBYTE)LocalAlloc(LPTR, cbHeader);
            if (pbHeader == NULL)
            {
                printf("- Allocation of pbHeader failed, Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }
            cbReqMessage = pvSizesStream.cbMaximumMessage;
            pbReqMessage = (PBYTE)LocalAlloc(LPTR, cbReqMessage);
            if (pbReqMessage == NULL)
            {
                printf("- Allocation of pbReqMessage failed, Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }
            cbTrailer = pvSizesStream.cbTrailer;
            pbTrailer = (PBYTE)LocalAlloc(LPTR, cbTrailer);
            if (pbTrailer == NULL)
            {
                printf("- Allocation of pbTrailer failed, Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }
        }
        else
        {
            cbReqMessage = pvSizesConnection.cbMaxToken;
            pbReqMessage = (PBYTE)LocalAlloc(LPTR, cbReqMessage);
            if (pbReqMessage == NULL)
            {
                printf("- Allocation of pbReqMessage failed, Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }
            cbTrailer = pvSizesConnection.cbSecurityTrailer;
            pbTrailer = (PBYTE)LocalAlloc(LPTR, cbTrailer);
            if (pbTrailer == NULL)
            {
                printf("- Allocation of pbTrailer failed, Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }
        }
    }
    else
    {
        if (!g_fConnectionMode)
        { // stream mode
            cbIoBufferLength = pvSizesStream.cbHeader +
                pvSizesStream.cbMaximumMessage +
                pvSizesStream.cbTrailer;
        } // if(!ConnectionMode)

        else
        { // connection mode
            cbIoBufferLength = pvSizesConnection.cbMaxToken + pvSizesConnection.cbSecurityTrailer;
        } // else(!g_fConnectionMode)

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
        if (!g_fConnectionMode && !g_fNoRecordLayer)
        {
            pbHeader = pbIoBuffer;
            cbHeader = pvSizesStream.cbHeader;
            pbReqMessage = pbIoBuffer + pvSizesStream.cbHeader;
        }
        else
        {
            pbReqMessage = pbIoBuffer;
        }
    }

    bSendZeroLengthApplicationData = g_fSendZeroLengthApplicationData;
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
        if (!g_fNonContiguousBuffers)
        {
            pbTrailer = pbReqMessage + cbReqMessage;

            if (!g_fConnectionMode)
            {
                cbTrailer = pvSizesStream.cbTrailer;
            }
            else
            {
                cbTrailer = pvSizesConnection.cbSecurityTrailer;
            }
        }

        //
        // Construct the message buffers for the HTTP Request
        //

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        if (g_fNoRecordLayer)
        {
            Buffers[0].pvBuffer = pbReqMessage;
            Buffers[0].cbBuffer = cbReqMessage;
            Buffers[0].BufferType = SECBUFFER_DATA;
        }
        else if (!g_fConnectionMode)
        {
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
        }
        else
        { // Connection Mode
            Buffers[0].pvBuffer = pbReqMessage;
            Buffers[0].cbBuffer = cbReqMessage;
            Buffers[0].BufferType = SECBUFFER_DATA;

            Buffers[1].pvBuffer = pbTrailer;
            Buffers[1].cbBuffer = cbTrailer;
            Buffers[1].BufferType = SECBUFFER_TOKEN;

            Buffers[2].BufferType = SECBUFFER_EMPTY;
            Buffers[2].cbBuffer = 0;
            Buffers[2].pvBuffer = NULL;

            Buffers[3].BufferType = SECBUFFER_ALERT;
            Buffers[3].cbBuffer = 255;
            Buffers[3].pvBuffer = rgbAlert;

            Buffers[4].BufferType = SECBUFFER_EMPTY;
        }

        // Encrypt the HTTP Request Message
        if (g_fNoRecordLayer &&
            pQuicApplicationKeys != NULL &&
            pQuicApplicationKeys->hClientWriteKey != NULL)
        {
            dwStatus = QuicEncrypt(
                pQuicApplicationKeys,
                FALSE,
                &Buffers[0]);
        }
  
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
        if (!g_fNonContiguousBuffers)
        {
            //contiguous buffers, send all at once
            if (!g_fConnectionMode)
            {
                if (fUseSockets)
                {
                    cbDataSent = send(
                        Socket,
                        (PCHAR)pbIoBuffer,
                        Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                        0);
                    g_dwNumServerSends++;
                }
                else
                {
                    cbDataSent = SendToServer((PCHAR)pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
                }
            }
            else
            {
                if (fUseSockets)
                {
                    cbDataSent = send(
                        Socket,
                        (PCHAR)pbIoBuffer,
                        Buffers[0].cbBuffer + Buffers[1].cbBuffer,
                        0);
                    g_dwNumServerSends++;
                }
                else
                {
                    cbDataSent = SendToServer((PCHAR)pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer);
                }
            }

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
        }
        else
        {
            //we have non-contiguous buffers; send them individually
            for (i = 0; i < (g_fConnectionMode ? 2 : 3); i++)
            {
                if (fUseSockets)
                {
                    cbDataSent = send(Socket,
                        (PCHAR)Buffers[i].pvBuffer,
                        Buffers[i].cbBuffer,
                        0);
                }
                else
                {
                    cbDataSent = SendToServer((PCHAR)Buffers[i].pvBuffer,
                        Buffers[i].cbBuffer);
                }

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
                PrintHexDump(cbDataSent, (PBYTE)Buffers[i].pvBuffer);
            }
            // increment only once, despite how many individual messages we send, as this is one flight
            if (fUseSockets)
            {
                g_dwNumServerSends++;
            }

        }

        if (bSendZeroLengthApplicationData)
        {
            bSendZeroLengthApplicationData = FALSE;
            // Now send the actual request.
            continue;
        }

        break;
    }


cleanup:
    if (g_fNonContiguousBuffers)
    {
        if (NULL != pbHeader)
        {
            LocalFree(pbHeader);
            pbHeader = NULL;
        }
        if (NULL != pbReqMessage)
        {
            LocalFree(pbReqMessage);
            pbReqMessage = NULL;
        }
        if (NULL != pbTrailer)
        {
            LocalFree(pbTrailer);
            pbTrailer = NULL;
        }
    }
    else
    {
        if (NULL != pbIoBuffer)
        {
            LocalFree(pbIoBuffer);
            pbIoBuffer = NULL;
        }
    }

    return dwStatus;

}

//============================================================
// SslAppendExtraData()
// Utility function to decrypt and append extra data, if needed
//
// This is currently copy+pasted from websrv.c with a couple of changes
// We should consider moving all of the Read/Send packet logic,
// as well as the SECBUFFER_EXTRA stuff, to a common lib.
//============================================================
unsigned long
SslAppendExtraData(
    IN CtxtHandle* phContext,
    IN OUT PBYTE pBuffer,
    IN OUT DWORD* pcbBuffer, //on input, this is the initial offset; on output, this is the length
    IN DWORD cbMaxBuffer,
    IN OUT PBYTE pbInitialExtraBuffer,
    IN DWORD cbInitialExtraBuffer,
    IN PQUIC_KEYS pQuicApplicationKeys)
{
    DWORD              dwStatus = SEC_E_OK;
    SecBufferDesc      Message = { 0 };
    SecBuffer          Buffers[5] = { 0 };
    SecBuffer* pDataBuffer = NULL;
    SecBuffer* pExtraBuffer = NULL;
    ULONG              i = 0;
    BYTE               rgbAlert[256] = { 0 };
    PBYTE              pbExtra = pbInitialExtraBuffer;

    DWORD cbExtra = cbInitialExtraBuffer;

    while (dwStatus == SEC_E_OK && cbExtra > 0)
    {
        //
        // Attempt to decrypt the received data.
        //
        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 5;
        Message.pBuffers = Buffers;

        if (!g_fConnectionMode || g_fNoRecordLayer)
        { // stream mode
            Buffers[0].BufferType = SECBUFFER_DATA;
            Buffers[0].pvBuffer = pbExtra;
            Buffers[0].cbBuffer = cbExtra;

            Buffers[1].BufferType = SECBUFFER_EMPTY;
            Buffers[1].pvBuffer = NULL;
            Buffers[1].cbBuffer = 0;
        }
        else
        { // connection mode
            Buffers[0].BufferType = SECBUFFER_DATA;
            Buffers[0].pvBuffer = pbExtra;
            Buffers[0].cbBuffer = cbExtra -
                pvSizesConnection.cbSecurityTrailer;

            Buffers[1].BufferType = SECBUFFER_TOKEN;
            Buffers[1].pvBuffer = pbExtra + cbExtra -
                pvSizesConnection.cbSecurityTrailer;
            Buffers[1].cbBuffer = pvSizesConnection.cbSecurityTrailer;
        }

        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[2].pvBuffer = NULL;
        Buffers[2].cbBuffer = 0;

        Buffers[3].BufferType = SECBUFFER_EMPTY;
        Buffers[3].pvBuffer = NULL;
        Buffers[3].cbBuffer = 0;

        Buffers[4].pvBuffer = rgbAlert;
        Buffers[4].BufferType = SECBUFFER_ALERT;
        Buffers[4].cbBuffer = sizeof(rgbAlert);

        if (g_fNoRecordLayer &&
            pQuicApplicationKeys != NULL &&
            pQuicApplicationKeys->hClientWriteKey != NULL)
        {
            dwStatus = QuicDecrypt(
                pQuicApplicationKeys,
                FALSE,
                &Buffers[0]);
        }

        dwStatus = DecryptMessage(
                phContext,
                &Message,
                0,
                NULL);
  
        printf("- DecryptMessage returned 0x%lx.\n", dwStatus);

        // incomplete message
        if (dwStatus == SEC_E_INCOMPLETE_MESSAGE)
        {
            goto cleanup;
        }

        // close_notify message received
        if (dwStatus == SEC_I_CONTEXT_EXPIRED)
        {
            printf("- SEC_I_CONTEXT_EXPIRED- Close notify message received.\n");

            // print the buffers to see if anything was returned
            for (i = 0; i < Message.cBuffers; i++)
            {
                printf("- Buffer %d (type:%d)\n", i, Buffers[i].BufferType);
                if (Buffers[i].BufferType != SECBUFFER_EMPTY &&
                    Buffers[i].BufferType != SECBUFFER_EXTRA)
                {
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }
            }

            goto cleanup;
        }

        // error case
        if (dwStatus != SEC_E_OK && dwStatus != SEC_I_RENEGOTIATE
            )
        {
            if (Buffers[4].cbBuffer != 0 && Buffers[4].BufferType == SECBUFFER_ALERT)
            {
                // We have an alert
                printf("SslReadPacket: ALERT was generated\n");
                PrintHexDump(Buffers[4].cbBuffer, (PBYTE)Buffers[4].pvBuffer);
            }

            printf("- Error 0x%x returned by DecryptMessage!\n", dwStatus);
            goto cleanup;
        }

        //
        // Loop over the 5 output buffers to
        // locate data and (optional) extra buffers.
        //
        pDataBuffer = NULL;
        pExtraBuffer = NULL;
        for (i = 0; i < Message.cBuffers; i++)
        {
            if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            {
                if (SEC_E_OK == dwStatus)
                {
                    printf("- %d bytes of SECBUFFER_DATA decrypted.\n", Buffers[i].cbBuffer);
                    printf("- SECBUFFER_DATA buffer:\n");
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }
                pDataBuffer = &Buffers[i];
                continue;
            }

            if (pExtraBuffer == NULL &&
                Buffers[i].BufferType == SECBUFFER_EXTRA)
            {
                pExtraBuffer = &Buffers[i];
                printf("- %d bytes of SECBUFFER_EXTRA decrypted.\n", Buffers[i].cbBuffer);
                PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                continue;
            }

            if (Buffers[i].BufferType != SECBUFFER_EXTRA &&
                Buffers[i].BufferType != SECBUFFER_DATA)
            {
                if (Buffers[i].BufferType == SECBUFFER_TOKEN)
                {
                    printf("- %d bytes of SECBUFFER_TOKEN decrypted.\n", Buffers[i].cbBuffer);
                    printf("- SECBUFFER_TOKEN buffer:\n");
                    PrintHexDump(Buffers[i].cbBuffer, (PBYTE)Buffers[i].pvBuffer);
                }
            }
            else if (Buffers[i].BufferType == SECBUFFER_EMPTY)
            {
                printf("- SECBUFFER_EMPTY.\n");
            }
            else
            {
                printf("UKNOWN Buffer Type %d.\n", Buffers[i].BufferType);
            }
        }
        //append buffer, loop around for more extra if needed
        if (*pcbBuffer + (pDataBuffer->cbBuffer) > cbMaxBuffer)
        {
            printf("Not enough buffer space\n");
            dwStatus = SEC_E_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        MoveMemory(pBuffer + *pcbBuffer, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
        *pcbBuffer = *pcbBuffer + pDataBuffer->cbBuffer;
        if (pExtraBuffer == NULL)
        {
            //no more data
            goto cleanup;
        }
        cbExtra = pExtraBuffer->cbBuffer;
        pbExtra = (PBYTE)pExtraBuffer->pvBuffer;
    }

cleanup:
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
    // Read data from server until done.
    //

    if (g_fSaveReceivedFile)
    {
        //
        // Initialize received file
        //

        hFile = CreateFileA(pszReceivedFileName,    // file to create
            GENERIC_WRITE,          // open for writing
            0,                      // do not share
            NULL,                   // default security
            CREATE_ALWAYS,          // overwrite existing
            FILE_ATTRIBUTE_NORMAL,  // normal file
            NULL);                  // no attr. template

        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("- Could not create file for received data\n");
            dwStatus = WEBCLI_ERROR_ERROR;
            goto cleanup;
        }
    }

    //
    // Allocate a working buffer based on sizes for stream/connection mode
    //

    if (!g_fConnectionMode || g_fNoRecordLayer)
    { // stream mode
        cbIoBufferLength = pvSizesStream.cbHeader +
            pvSizesStream.cbMaximumMessage +
            pvSizesStream.cbTrailer;
    } // if(!ConnectionMode)

    else
    { // connection mode
        cbIoBufferLength = pvSizesConnection.cbMaxToken +
            pvSizesConnection.cbSecurityTrailer;
    } // else(!g_fConnectionMode)

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

        // Check if empty message was sent. The test server should be sending this
        // message first.
        if (g_ftestEmptyMessage)
        {
            // The size of the buffer received should be 0. And the data should
            // also be 0.
            printf("- Test Empty Message : Recevied data buffer:\n");
            PrintHexDump(cbIoBuffer, pbIoBuffer);
            printf("Size of message received = %d\n", cbIoBuffer);
            if (cbIoBuffer > 0)
            {
                printf(" TestEmptyMessage failed. Client recevied %d bytes of data\n", cbIoBuffer);
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;

            }
            g_ftestEmptyMessage = FALSE;
            continue;
        }

        // Test for server speaks first message.
        if (fHeader &&
            g_fNoRecordLayer &&
            cbIoBuffer >= SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE &&
            RtlCompareMemory(
                pbIoBuffer,
                SERVER_SPEAKS_FIRST_MESSAGE_PREFIX,
                SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE) == SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE)
        {
            if (g_pszServerSpeaksFirst != NULL)
            {
                cbIoBuffer -= SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE;
                DWORD dwServerSpeaksFirstMessageSize = strlen(g_pszServerSpeaksFirst) + sizeof(ANSI_NULL);

                fReceivedExpectedServerSpeaksFirstMessage =
                    cbIoBuffer == dwServerSpeaksFirstMessageSize &&
                    RtlCompareMemory(
                        pbIoBuffer + SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE,
                        g_pszServerSpeaksFirst,
                        dwServerSpeaksFirstMessageSize) == dwServerSpeaksFirstMessageSize;
            }

            // Move any "extra" data to the input buffer.
            if (!g_fConnectionMode && pbExtra != NULL)
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

        // server wants client auth, renegotiation required
        if (dwStatus == SEC_I_RENEGOTIATE)
        {
            if (g_fEncryptAfterPostHandshake)
            {
                printf("- EncryptAfterPostHandshake- Trying to send data after receiving SEC_I_RENEGOTIATE 0x%x\n", dwStatus);
                // Send the request again to simulate sending data (EncryptMessage) after renegotiate.
                dwStatus = HttpsSendRequest(
                    Socket,
                    phCreds,
                    phContext,
                    pszFileName,
                    pQuicApplicationKeys);
                if (WEBCLI_ERROR_SUCCESS != dwStatus)
                {
                    printf("- EncryptAfterPostHandshake- Failed to send data after receiving SEC_I_RENEGOTIATE, HttpsSendRequest returned 0x%x\n",
                        dwStatus);
                    return dwStatus;
                }
                g_fEncryptAfterPostHandshake = FALSE;
            }

            if (g_dwNegotiatedProtocol == SP_PROT_TLS1_3_CLIENT)
            {
                // TLS 1.3 post-handshake message needs to be handled in LSASS.
                printf("- Server sent a post-handshake message!\n");
            }
            else
            {
                // The server wants to perform another handshake sequence.
                printf("- Server requested renegotiation!\n");
            }

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
            (fEmptyAppDataReceived && g_fAcceptZeroLengthApplicationData))
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
                    if (!g_fConnectionMode)
                    {
                        if (pbExtra)
                        {
                            MoveMemory(pbIoBuffer, pbExtra, cbExtra);
                            cbIoBuffer = cbExtra;
                        }
                        else
                        {
                            cbIoBuffer = 0;
                        }
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
                    if (!g_fIgnoreHttpError)
                    {
                        dwStatus = WEBCLI_ERROR_ERROR;
                    }
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
                if (g_fSaveReceivedFile)
                {
                    fSuccess = WriteFile(hFile,
                        pbIoBuffer,
                        cbIoBuffer,
                        &cbContentWritten,
                        NULL);

                    if (!fSuccess)
                    {
                        printf("- Failed writing received file to disk with error %ld\n", GetLastError());
                        dwStatus = WEBCLI_ERROR_ERROR;
                        goto cleanup;
                    }
                }
            }

        }

        // Move any "extra" data to the input buffer.
        if (!g_fConnectionMode && pbExtra != NULL)
        {
            MoveMemory(pbIoBuffer, pbExtra, cbExtra);
            cbIoBuffer = cbExtra;
        }
        else
        {
            cbIoBuffer = 0;
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

    // At this point check if extra data
    // is received from peer
    if (g_fVerifyExtraRecord == TRUE)
    {
        if (g_fExtraDataReceived == FALSE)
        {
            printf("- ERROR! Extra record not received from server.\n");
            dwStatus = WEBCLI_ERROR_ERROR;
            goto cleanup;
        }
        else        // Reset the g_fExtraDataReceived flag to verify the same for the next request
        {
            g_fExtraDataReceived = FALSE;
        }
    }

    if (g_fNoRecordLayer &&
        g_pszServerSpeaksFirst != NULL &&
        !fReceivedExpectedServerSpeaksFirstMessage)
    {
        dwStatus = WEBCLI_ERROR_ERROR;
        goto cleanup;
    }

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

    if (g_fSaveReceivedFile && hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    return dwStatus;

} // end HttpsGetFile()

// error and success codes definition
#define WEBCLI_ERROR_SUCCESS     0
#define WEBCLI_ERROR_ERROR       -1

//*********************************************************************
// Build and Send Alert messages
//*********************************************************************
unsigned long
BuildSchannelAlert(
    IN     PCredHandle     phCreds,
    IN     CtxtHandle* phContext,
    IN     DWORD           dwAlertType,
    IN     DWORD           dwAlertNumber,
    OUT PBYTE* ppbMessage,
    OUT DWORD* pcbMessage)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    DWORD           dwType = 0;
    PBYTE           pbMessage = NULL;
    DWORD           cbMessage = 0;
    DWORD           cbData = 0;

    SecBufferDesc   OutBuffer = { 0 };
    SecBuffer       OutBuffers[1] = { 0 };
    DWORD           dwSSPIFlags = 0;
    DWORD           dwSSPIOutFlags = 0;
    TimeStamp       tsExpiry = { 0 };
    PBYTE           pbToken = NULL;
    DWORD           cbToken = 0;

    SCHANNEL_ALERT_TOKEN Token = { 0 };

    Token.dwTokenType = SCHANNEL_ALERT;
    Token.dwAlertType = dwAlertType;
    Token.dwAlertNumber = dwAlertNumber;

    OutBuffers[0].pvBuffer = &Token;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(Token);

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    dwStatus = ApplyControlToken(phContext, &OutBuffer);

    if (FAILED(dwStatus))
    {
        printf("- Error 0x%x returned by ApplyControlToken!\n", dwStatus);
        goto cleanup;
    }

    dwSSPIFlags =
        ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        (g_fAllocateMemory ? 0 : ISC_REQ_ALLOCATE_MEMORY) |
        (g_fConnectionMode ? ISC_REQ_CONNECTION : ISC_REQ_STREAM);

    if (g_fAllocateMemory) 
    {
        pbToken = (PBYTE)DbglibLocalAlloc(g_dwMaxToken);
        if (NULL == pbToken)
        {
            dwStatus = ERROR_NOT_ENOUGH_MEMORY;
            printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
            goto cleanup;
        }
        cbToken = g_dwMaxToken;
    }

    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].pvBuffer = pbToken;
    OutBuffers[0].cbBuffer = cbToken;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    dwStatus = InitializeSecurityContextA(
        phCreds,
        phContext,
        NULL,
        dwSSPIFlags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &OutBuffer,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (FAILED(dwStatus))
    {
        printf("- Error 0x%x returned by InitializeSecurityContext!\n", dwStatus);
        goto cleanup;
    }

    *ppbMessage = (PBYTE)OutBuffers[0].pvBuffer;
    *pcbMessage = OutBuffers[0].cbBuffer;

    return dwStatus;

cleanup:

    FreeOutputBuffer(&OutBuffers[0]);

    return dwStatus;
}

/**********************************************************************
 Build and Send Alert messages
**********************************************************************/
unsigned long
BuildAndSendAlert(
    IN     SOCKET          Socket,
    IN     PCredHandle     phCreds,
    IN     PCtxtHandle     phContext,
    IN     DWORD           ErrorReturned)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    PBYTE           pbMessage = NULL;
    DWORD           cbMessage = 0;
    DWORD           cbData = 0;
    DWORD           dwAlertType = 0;
    DWORD           dwAlertNumber = 0;

    switch (ErrorReturned)
    {
    case CERT_E_REVOKED:
        dwAlertType = TLS1_ALERT_FATAL;
        dwAlertNumber = TLS1_ALERT_CERTIFICATE_REVOKED;
        break;

    case CERT_E_EXPIRED:
    case CERT_E_VALIDITYPERIODNESTING:
        dwAlertType = TLS1_ALERT_FATAL;
        dwAlertNumber = TLS1_ALERT_CERTIFICATE_EXPIRED;
        break;

    case CERT_E_UNTRUSTEDROOT:
        dwAlertType = TLS1_ALERT_FATAL;
        dwAlertNumber = TLS1_ALERT_UNKNOWN_CA;
        break;

    default:
        dwAlertType = TLS1_ALERT_FATAL;
        dwAlertNumber = TLS1_ALERT_CERTIFICATE_UNKNOWN;
    }

    dwStatus = BuildSchannelAlert(
        phCreds,
        phContext,
        dwAlertType,
        dwAlertNumber,
        &pbMessage,
        &cbMessage);
    if (SEC_E_OK != dwStatus)
    {
        printf("- Building alert msg FAILED!\n");
        goto cleanup;
    }

    //
    // Send the alert to the server.
    //

    if (pbMessage != NULL && cbMessage != 0)
    {
        if (fUseSockets)
        {
            cbData = send(Socket, (LPCSTR)pbMessage, cbMessage, 0);
        }
        else
        {
            cbData = SendToServer((LPSTR)pbMessage, cbMessage);
        }

        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            dwStatus = WSAGetLastError();
            printf("- Error %d sending alert!\n", dwStatus);
            goto cleanup;
        }

        printf("- %d bytes of ALERT handshake data sent.\n", cbData);
        printf("- ALERT handshake buffer:\n");
        PrintHexDump(cbData, pbMessage);
    }

cleanup:

    // Free output buffer.
    //pfnFreeContextBuffer(pbMessage);

    return dwStatus;
}

/*********************************************************************
 Reconnects can be disabled to a session, forcing fullhandshakes
*********************************************************************/
unsigned long
DisableReconnects(
    IN     PCtxtHandle phContext)
{
    DWORD                   dwStatus = WEBCLI_ERROR_ERROR;
    SCHANNEL_SESSION_TOKEN  SessionToken = { 0 };
    SecBufferDesc           OutBuffer = { 0 };
    SecBuffer               OutBuffers[1] = { 0 };


    if (NULL == phContext)
    {
        printf("- Context Handle is NULL!\n");
        return dwStatus;
    }

    // prepare the message
    SessionToken.dwTokenType = SCHANNEL_SESSION;
    if (g_fDisableReconnects)
    {
        SessionToken.dwFlags = SSL_SESSION_DISABLE_RECONNECTS;
    }
    else
    {
        SessionToken.dwFlags = SSL_SESSION_ENABLE_RECONNECTS;
    }

    OutBuffers[0].pvBuffer = &SessionToken;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(SessionToken);

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    dwStatus = ApplyControlToken(phContext, &OutBuffer);

    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x setting no cache attribute!\n", dwStatus);
    }
    else
    {
        printf("- Reconnects disabled\n");
    }

    return dwStatus;
} // DisableReconnects()

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
    if (fUseSockets && Socket == INVALID_SOCKET ||
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
            if (fUseSockets)
            {
                cbData = recv(Socket, (LPSTR)pbIoBuffer, cbIoBuffer, 0);
            }
            else
            {
                cbData = ReceiveFromServer((LPSTR)pbIoBuffer, cbIoBuffer);
            }
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


/**********************************************************************
 Send a close notify
**********************************************************************/
DWORD
DisconnectFromServer(
    IN     SOCKET         Socket,
    IN     PCredHandle    phCreds,
    IN     CtxtHandle* phContext,
    IN     PQUIC_KEYS     pQuicApplicationKeys)
{
    DWORD           dwStatus = WEBCLI_ERROR_ERROR;
    DWORD           dwType;
    PBYTE           pbMessage = NULL;
    DWORD           cbMessage = 0;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;

    //
    // Kernel Mode or using the new QOP
    //

    if (g_fUseNewQOP)
    {
        SecBufferDesc   Message;
        SecBuffer       Buffers[4];
        BYTE            CloseNotify[2] = { TLS1_ALERT_WARNING, TLS1_ALERT_CLOSE_NOTIFY };
        //close_notify is {1, 0};

        //
        // Allocate memory for encrypted close_notify message
        //

        if (!g_fConnectionMode || g_fNoRecordLayer)
        {
            cbMessage = pvSizesStream.cbHeader + sizeof(CloseNotify)
                + pvSizesStream.cbTrailer;
        }
        else
        {
            cbMessage = sizeof(CloseNotify) +
                pvSizesConnection.cbSecurityTrailer;
        }

        pbMessage = (PBYTE)LocalAlloc(LPTR, cbMessage);

        if (pbMessage == NULL)
        {
            printf("- Out of memory!\n");
            goto cleanup;
        }

        //
        // Encrypt the close_notify message.
        //

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        if (g_fNoRecordLayer)
        {
            Buffers[0].pvBuffer = pbMessage;
            Buffers[0].cbBuffer = sizeof(CloseNotify);
            Buffers[0].BufferType = SECBUFFER_DATA;
        }
        else if (!g_fConnectionMode)
        {
            Buffers[0].pvBuffer = pbMessage;
            Buffers[0].cbBuffer = pvSizesStream.cbHeader;
            Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

            Buffers[1].pvBuffer = pbMessage + pvSizesStream.cbHeader;
            Buffers[1].cbBuffer = sizeof(CloseNotify);
            Buffers[1].BufferType = SECBUFFER_DATA;

            memcpy(Buffers[1].pvBuffer, &CloseNotify, sizeof(CloseNotify));

            Buffers[2].pvBuffer = pbMessage + pvSizesStream.cbHeader +
                sizeof(CloseNotify);
            Buffers[2].cbBuffer = pvSizesStream.cbTrailer;
            Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        }
        else
        {
            Buffers[0].pvBuffer = pbMessage;
            Buffers[0].cbBuffer = sizeof(CloseNotify);
            Buffers[0].BufferType = SECBUFFER_DATA;

            memcpy(Buffers[0].pvBuffer, &CloseNotify, sizeof(CloseNotify));

            Buffers[1].pvBuffer = pbMessage + sizeof(CloseNotify);
            Buffers[1].cbBuffer = pvSizesConnection.cbSecurityTrailer;
            Buffers[1].BufferType = SECBUFFER_TOKEN;

            Buffers[2].BufferType = SECBUFFER_EMPTY;
        }

        // common to both modes
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        // Encrypt the HTTP Request Message
        if (g_fNoRecordLayer &&
            pQuicApplicationKeys != NULL &&
            pQuicApplicationKeys->hClientWriteKey != NULL)
        {
            dwStatus = QuicEncrypt(
                pQuicApplicationKeys,
                FALSE,
                &Buffers[0]);
        }

        dwStatus = EncryptMessage(
                phContext,
                SECQOP_WRAP_OOB_DATA,
                &Message,
                0);

        if (FAILED(dwStatus))
        {
            printf("- Encrypting Close Notify Alert failed with 0x%x!\n", dwStatus);
            goto cleanup;
        }
        else
        {
            printf("- Sending Encrypted Close Notify Alert\n");
        }

        cbMessage = Buffers[0].cbBuffer + Buffers[1].cbBuffer
            + Buffers[2].cbBuffer;
    }


    //
    // Old method of generating close_notify using ApplyControlToken
    // (only in User mode)
    //
    else
    {

        //
        // Notify schannel that we are about to close the connection.
        //

        dwType = SCHANNEL_SHUTDOWN;

        OutBuffers[0].pvBuffer = &dwType;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = sizeof(dwType);

        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        dwStatus = ApplyControlToken(phContext, &OutBuffer);

        if (FAILED(dwStatus))
        {
            printf("- Error 0x%x returned by ApplyControlToken!\n", dwStatus);
            goto cleanup;
        }

        //
        // Build an SSL close notify message.
        //

        dwSSPIFlags =
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY |
            ISC_RET_EXTENDED_ERROR |
            (g_fAllocateMemory ? 0 : ISC_REQ_ALLOCATE_MEMORY) |
            (g_fConnectionMode ? ISC_REQ_CONNECTION : ISC_REQ_STREAM);

        if (g_fAllocateMemory)
        {
            pbMessage = (PBYTE)DbglibLocalAlloc(g_dwMaxToken);
            if (NULL == pbMessage)
            {
                dwStatus = ERROR_NOT_ENOUGH_MEMORY;
                printf("- Error 0x%x returned by LocalAlloc\n", dwStatus);
                goto cleanup;
            }
            cbMessage = g_dwMaxToken;
        }

        OutBuffers[0].pvBuffer = pbMessage;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = cbMessage;

        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        dwStatus = InitializeSecurityContextA(
            phCreds,
            phContext,
            NULL,
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            NULL,
            0,
            phContext,
            &OutBuffer,
            &dwSSPIOutFlags,
            &tsExpiry);

        printf("- ISC returned 0x%lx.\n", dwStatus);

        if (FAILED(dwStatus))
        {
            printf("- Error 0x%x returned by InitializeSecurityContext!\n", dwStatus);
            goto cleanup;
        }

        pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
        cbMessage = OutBuffers[0].cbBuffer;

    } // else using ApplyControlToken (User mode)

    //
    // Send the close notify message to the server.
    //

    if (pbMessage != NULL && cbMessage != 0)
    {
        if (fUseSockets)
        {
            cbData = send(Socket,
                (LPCSTR)pbMessage,
                cbMessage,
                0);
            //
            // Making this error non fatal as it is not required that both
            // sides wait for a close_notify before graceful connection closure
            // This is a best effort send
            //
            if (cbData == SOCKET_ERROR || cbData == 0)
            {
                printf("- Socket Error %d sending close notify!\n",
                    WSAGetLastError());
                goto cleanup;
            }
        }
        else
        {
            cbData = SendToServer((LPSTR)pbMessage, cbMessage);
        }

        printf("- %d bytes of close notify handshake data sent.\n",
            cbData);
        printf("- close_notify buffer:\n");
        PrintHexDump(cbData, pbMessage);
    }

cleanup:

    //pfnFreeContextBuffer(pbMessage);

    return dwStatus;
} // DisconnectFromServer

/*########### SERVER CERTIFICATE VALIDATION STARTS ##################*/

/**********************************************************************
 Map and Print WinVerifyTrust error
**********************************************************************/
void DisplayWinVerifyTrustError(DWORD dwStatus)
{
    LPSTR pszName = NULL;

    switch (dwStatus)
    {

    case CERT_E_EXPIRED:
        pszName = (LPSTR)"CERT_E_EXPIRED";
        break;
    case CERT_E_VALIDITYPERIODNESTING:
        pszName = (LPSTR)"CERT_E_VALIDITYPERIODNESTING";
        break;
    case CERT_E_ROLE:
        pszName = (LPSTR)"CERT_E_ROLE";
        break;
    case CERT_E_PATHLENCONST:
        pszName = (LPSTR)"CERT_E_PATHLENCONST";
        break;
    case CERT_E_CRITICAL:
        pszName = (LPSTR)"CERT_E_CRITICAL";
        break;
    case CERT_E_PURPOSE:
        pszName = (LPSTR)"CERT_E_PURPOSE";
        break;
    case CERT_E_ISSUERCHAINING:
        pszName = (LPSTR)"CERT_E_ISSUERCHAINING";
        break;
    case CERT_E_MALFORMED:
        pszName = (LPSTR)"CERT_E_MALFORMED";
        break;
    case CERT_E_UNTRUSTEDROOT:
        pszName = (LPSTR)"CERT_E_UNTRUSTEDROOT";
        break;
    case CERT_E_CHAINING:
        pszName = (LPSTR)"CERT_E_CHAINING";
        break;
    case TRUST_E_FAIL:
        pszName = (LPSTR)"TRUST_E_FAIL";
        break;
    case CERT_E_REVOKED:
        pszName = (LPSTR)"CERT_E_REVOKED";
        break;
    case CERT_E_UNTRUSTEDTESTROOT:
        pszName = (LPSTR)"CERT_E_UNTRUSTEDTESTROOT";
        break;
    case CERT_E_REVOCATION_FAILURE:
        pszName = (LPSTR)"CERT_E_REVOCATION_FAILURE";
        break;
    case CERT_E_CN_NO_MATCH:
        pszName = (LPSTR)"CERT_E_CN_NO_MATCH";
        break;
    case CERT_E_WRONG_USAGE:
        pszName = (LPSTR)"CERT_E_WRONG_USAGE";
        break;
    default:
        pszName = (LPSTR)"(unknown)";
        break;
    }

    printf("WVT Error: 0x%x - %s!\n", dwStatus, pszName);
} // DisplayWinVerifyTrustError()

/**********************************************************************
 Verify the server certificate manually
**********************************************************************/
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;

    LPSTR rgszUsages[] = { (LPSTR)szOID_PKIX_KP_SERVER_AUTH,
        (LPSTR)szOID_SERVER_GATED_CRYPTO,
        (LPSTR)szOID_SGC_NETSCAPE };

    DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

    PWSTR   pwszServerName = NULL;
    DWORD   cchServerName;
    DWORD   dwStatus;

    //
    // Check for server certificate.
    //

    if (pServerCert == NULL)
    {
        dwStatus = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    //
    // Convert server name to unicode.
    //

    if (pszServerName == NULL || strlen(pszServerName) == 0)
    {
        dwStatus = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName,
        -1, NULL, 0);

    pwszServerName = (PWSTR)LocalAlloc(LPTR, cchServerName * sizeof(WCHAR));
    if (pwszServerName == NULL)
    {
        dwStatus = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName,
        -1, pwszServerName, cchServerName);
    if (cchServerName == 0)
    {
        dwStatus = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    if (!CertGetCertificateChain(
        NULL,
        pServerCert,
        NULL,
        pServerCert->hCertStore,
        &ChainPara,
        0,
        NULL,
        &pChainContext)
        )
    {
        dwStatus = GetLastError();
        printf("- CertGetCertificateChain FAILED!\n");
        //PrintSecurityError(dwStatus);
        goto cleanup;
    }

    //
    // Validate certificate chain.
    //

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType = AUTHTYPE_SERVER;
    polHttps.fdwChecks = dwCertFlags;
    polHttps.pwszServerName = pwszServerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    printf("- Using CertVerifyCertificateChainPolicy.\n");

    if (!CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL,
        pChainContext,
        &PolicyPara,
        &PolicyStatus)
        )
    {
        dwStatus = GetLastError();
        printf("- CertVerifyCertificateChainPolicy FAILED!\n");
        DisplayWinVerifyTrustError(dwStatus);
        goto cleanup;
    }

    if (PolicyStatus.dwError)
    {
        dwStatus = PolicyStatus.dwError;
        printf("- PolicyStatus.dwError is set.\n");
        DisplayWinVerifyTrustError(dwStatus);
        goto cleanup;
    }

    dwStatus = SEC_E_OK;
    printf("- Manual server cert validation passed.\n");

cleanup:

    if (pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (pwszServerName)
    {
        LocalFree(pwszServerName);
        pwszServerName = NULL;
    }

    return dwStatus;
} // VerifyCertificateChain()


/**********************************************************************
 Use WinVerifyTrust to verify the server certificate
**********************************************************************/
DWORD
VerifyServerCertificateWVT(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    DWORD                    dwStatus       = MYDBG_ERROR_ERROR;
    PWSTR                    pwszServerName = NULL;
    DWORD                    cchServerName  = 0;
    WINTRUST_DATA            sWTD;
    WINTRUST_CERT_INFO       sWTCI;
    HTTPSPolicyCallbackData  polHttps;
    GUID                     gHTTPS         = HTTPSPROV_ACTION;

    //
    // Check for server certificate.
    //
    if (NULL == pServerCert)
    {
        printf("- Server cert is NULL!\n");
        dwStatus = MYDBG_ERROR_BADPARAMETER;
        goto cleanup;
    }

    //
    // Convert server name to unicode.
    //

    if (pszServerName == NULL || strlen(pszServerName) == 0)
    {
        dwStatus = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);

    pwszServerName = (PWSTR)LocalAlloc(LPTR, cchServerName * sizeof(WCHAR));
    if (pwszServerName == NULL)
    {
        dwStatus = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if (cchServerName == 0)
    {
        dwStatus = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    //
    // Validate certificate chain.
    //
    memset(&sWTD, 0x00, sizeof(WINTRUST_DATA));
    sWTD.cbStruct = sizeof(WINTRUST_DATA);
    sWTD.dwUIChoice = WTD_UI_NONE;
    sWTD.pPolicyCallbackData = (LPVOID)&polHttps;
    sWTD.dwUnionChoice = WTD_CHOICE_CERT;
    sWTD.pCert = &sWTCI;
    sWTD.pwszURLReference = NULL;
    sWTD.fdwRevocationChecks = WTD_REVOKE_NONE;

    memset(&sWTCI, 0x00, sizeof(WINTRUST_CERT_INFO));
    sWTCI.cbStruct = sizeof(WINTRUST_CERT_INFO);
    sWTCI.psCertContext = (CERT_CONTEXT*)pServerCert;
    sWTCI.chStores = 1;
    sWTCI.pahStores = (HCERTSTORE*)&pServerCert->hCertStore;
    sWTCI.pcwszDisplayName = pwszServerName;

    memset(&polHttps, 0x00, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType = AUTHTYPE_SERVER;
    polHttps.fdwChecks = 0;
    polHttps.pwszServerName = pwszServerName;

    printf("- Using WinVerifyTrust.\n");

    dwStatus = WinVerifyTrust(NULL, &gHTTPS, &sWTD);

    if (dwStatus != ERROR_SUCCESS)
    {
        printf("- WinVerifyTrust FAILED to verify server cert!\n");
        DisplayWinVerifyTrustError(dwStatus);
        goto cleanup;
    }

    printf("- WinVerifyTrust server cert validation passed.\n");

cleanup:

    if (pwszServerName)
    {
        LocalFree(pwszServerName);
        pwszServerName = NULL;
    }

    return dwStatus;
} // VerifyServerCertificateWVT


CHAR* DecodeOCSPresponseStatus(DWORD dwStatus)
{
    CHAR* pszResponseStatus = NULL;

    switch (dwStatus)
    {
    case 0:
        pszResponseStatus = (LPSTR)"OCSP_SUCCESSFUL_RESPONSE";
        break;
    case 1:
        pszResponseStatus = (LPSTR)"OCSP_MALFORMED_REQUEST_RESPONSE";
        break;
    case 2:
        pszResponseStatus = (LPSTR)"OCSP_INTERNAL_ERROR_RESPONSE";
        break;
    case 3:
        pszResponseStatus = (LPSTR)"OCSP_TRY_LATER_RESPONSE";
        break;
        // 4 is not used
    case 5:
        pszResponseStatus = (LPSTR)"OCSP_SIG_REQUIRED_RESPONSE";
        break;
    case 6:
        pszResponseStatus = (LPSTR)"OCSP_UNAUTHORIZED_RESPONSE";
        break;
    default:
        pszResponseStatus = (LPSTR)"Error";

    }

    return pszResponseStatus;
}

DWORD
DecodeOCSPStaplingInfo(PCRYPT_DATA_BLOB encResponse)
{
    CRYPT_DATA_BLOB encodedResponse = *encResponse;

    BOOL fResult;
    DWORD dwLastErr = 0;
    HRESULT hr = E_FAIL;

    DWORD dwCountResponseEntry = 0;
    POCSP_RESPONSE_INFO pOcspResponseInfo = NULL;
    POCSP_SIGNATURE_INFO pSignatureInfo = NULL;
    PCCRYPT_OID_INFO pInfo;     // Don't free, its shared
    POCSP_BASIC_SIGNED_RESPONSE_INFO pOcspBasicSignedResponseInfo = NULL;
    POCSP_BASIC_RESPONSE_INFO pOcspBasicResponseInfo = NULL;
    OCSP_BASIC_RESPONSE_ENTRY const* pResponseEntry = NULL;

    DWORD dwStatus, cbInfo = 0;
    DWORD dwCertStatus;

    BOOL bCritical = TRUE;

    memset((void*)&pInfo, 0, sizeof(PCCRYPT_OID_INFO));

    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        OCSP_RESPONSE,
        encodedResponse.pbData,
        encodedResponse.cbData,
        CRYPT_DECODE_NOCOPY_FLAG |
        CRYPT_DECODE_ALLOC_FLAG |
        CRYPT_DECODE_SHARE_OID_STRING_FLAG,
        NULL,
        (void*)&pOcspResponseInfo,
        &cbInfo
    ))
    {
        dwStatus = GetLastError();
        printf("- CrytDecodeObjectEx failed: Error 0x%x\n", dwStatus);
        printf("- CrytDecodeObjectEx failed : cbData 0x % x\n", encodedResponse.cbData);
        dwStatus = MYDBG_ERROR_ERROR;
        return dwStatus;
    }

    if (NULL == pOcspResponseInfo)
    {
        printf(" OcspResponseInfo is NULL\n");
        dwStatus = MYDBG_ERROR_ERROR;
        return dwStatus;
    }

    if ((OCSP_SUCCESSFUL_RESPONSE != pOcspResponseInfo->dwStatus))
    {
        if ((pOcspResponseInfo->dwStatus == OCSP_UNAUTHORIZED_RESPONSE))
        {
            printf("OCSP_UNAUTHORIZED_RESPONSE \n");
            goto SuccessReturn;
        }
        else
        {
            if ((pOcspResponseInfo->dwStatus == OCSP_MALFORMED_REQUEST_RESPONSE))
            {
                printf("OCSP_MALFORMED_REQUEST_RESPONSE\n");
                goto SuccessReturn;
            }
            else
            {
                printf(" InvalidResponseStatus %d\n", pOcspResponseInfo->dwStatus);
                goto ErrorReturn;
            }
        }
    }

    printf("OCSP Response is : %s\n", DecodeOCSPresponseStatus(pOcspResponseInfo->dwStatus));

    if (NULL == pOcspResponseInfo->pszObjId)
    {
        printf("pOcspResponseInfo->pszObjId : MissingResponseOID\n");
        goto ErrorReturn;
    }
    if (0 != strcmp(pOcspResponseInfo->pszObjId, szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE))
    {
        printf("pOcspResponseInfo->pszObjId : UnsupportedResponseOID\n");
        goto ErrorReturn;
    }

    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        OCSP_BASIC_SIGNED_RESPONSE,
        pOcspResponseInfo->Value.pbData,
        pOcspResponseInfo->Value.cbData,
        CRYPT_DECODE_NOCOPY_FLAG |
        CRYPT_DECODE_ALLOC_FLAG |
        CRYPT_DECODE_SHARE_OID_STRING_FLAG,
        NULL,
        (void*)&pOcspBasicSignedResponseInfo,
        &cbInfo
    ))
    {
        dwStatus = GetLastError();
        printf("- CrytDecodeObjectEx failed: Error 0x%x\n", dwStatus);
        dwStatus = MYDBG_ERROR_ERROR;
        goto ErrorReturn;
    }

    if (NULL == pOcspBasicSignedResponseInfo)
    {
        printf(" pOcspBasicSignedResponseInfo is NULL\n");
        goto ErrorReturn;
    }

    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        OCSP_BASIC_RESPONSE,
        pOcspBasicSignedResponseInfo->ToBeSigned.pbData,
        pOcspBasicSignedResponseInfo->ToBeSigned.cbData,
        CRYPT_DECODE_NOCOPY_FLAG |
        CRYPT_DECODE_ALLOC_FLAG |
        CRYPT_DECODE_SHARE_OID_STRING_FLAG,
        NULL,
        (VOID**)&pOcspBasicResponseInfo,
        &cbInfo))
    {
        dwStatus = GetLastError();
        printf("- CrytDecodeObjectEx failed: Error 0x%x\n", dwStatus);
        dwStatus = MYDBG_ERROR_ERROR;
        goto ErrorReturn;
    }

    if (NULL == pOcspBasicResponseInfo)
    {
        printf(" pOcspBasicResponseInfo is NULL\n");
        goto ErrorReturn;
    }

    for (dwCountResponseEntry = 0; dwCountResponseEntry < pOcspBasicResponseInfo->cResponseEntry; dwCountResponseEntry++)
    {
        pResponseEntry = &pOcspBasicResponseInfo->rgResponseEntry[dwCountResponseEntry];
        printf("ResponseEntry %d\n", dwCountResponseEntry);

        if (NULL == pResponseEntry)
        {
            printf("ResponseEntry %d NUll: Error \n", dwCountResponseEntry);
            dwStatus = MYDBG_ERROR_ERROR;
            goto ErrorReturn;
        }

        dwCertStatus = pResponseEntry->dwCertStatus;

        switch (pResponseEntry->dwCertStatus)
        {
        case OCSP_BASIC_GOOD_CERT_STATUS:
            printf("CertStatus: GOOD\n");
            break;
        case OCSP_BASIC_REVOKED_CERT_STATUS:
            printf("CertStatus: REVOKED\n");
            break;
        case OCSP_BASIC_UNKNOWN_CERT_STATUS:
        default:
            printf("CertStatus: UNKNOWN\n");
            break;
        }
    }
    //Check nonce
    {
        DWORD dwCount = 0;
        BOOL bNoncePresent = FALSE;
        for (; dwCount < pOcspBasicResponseInfo->cExtension; dwCount++)
        {
            if (0 == strcmp(pOcspBasicResponseInfo->rgExtension[dwCount].pszObjId, szOID_PKIX_OCSP_NONCE))
            {
                printf(" NONCE is present: yes  and if critical: 0x%x\n", pOcspBasicResponseInfo->rgExtension[dwCount].fCritical);
                bNoncePresent = TRUE;
            }
        }
        if (!bNoncePresent)
            printf("\n NONCE is absent\n");
    }

SuccessReturn:
    fResult = TRUE;
    goto CommonReturn;

ErrorReturn:
    fResult = FALSE;

CommonReturn:
    dwLastErr = GetLastError();
    SetLastError(dwLastErr);
    return dwLastErr;
}

/**********************************************************************
 Checks that the server subject name matches the one specified by
 the caller.
**********************************************************************/
DWORD
VerifyServerCertSubjectName(IN PCtxtHandle phContext)
{
    DWORD dwStatus = MYDBG_ERROR_ERROR;
    PCCERT_CONTEXT pRemoteCertContext = NULL;
    LPSTR szCertSubjectName = NULL; // Buffer for receiving new name
    DWORD cchSubjectName = 0;
    DWORD dwCertGetNameFlags = 0;

    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x querying remote certificate!\n", dwStatus);
        goto cleanup;
    }

    // Get required Length of buffer to receive string
    dwCertGetNameFlags = CERT_SIMPLE_NAME_STR;
    cchSubjectName = CertGetNameString(
        pRemoteCertContext,
        CERT_NAME_RDN_TYPE,
        0,
        (PVOID)&dwCertGetNameFlags,
        NULL,
        0);

    szCertSubjectName = (LPSTR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cchSubjectName * sizeof(CHAR));

    if (NULL == szCertSubjectName)
    {
        dwStatus = MYDBG_ERROR_OUTOFMEMORY;
        goto cleanup;
    }

    cchSubjectName = CertGetNameStringA(
        pRemoteCertContext,
        CERT_NAME_RDN_TYPE,
        0,
        (PVOID)&dwCertGetNameFlags,
        szCertSubjectName,
        cchSubjectName);

    if (0 == cchSubjectName)
    {
        printf("- Error No subject name found on remote certificate\n");
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }
    else if (0 != _strcmpi(szCertSubjectName, g_pszSrvCertNameToVerify))
    {
        printf("- Remote certificate subject name %s does not match the expected subject name %s. \n",
            g_pszSrvCertNameToVerify,
            szCertSubjectName);
        dwStatus = MYDBG_ERROR_ERROR;
        goto cleanup;
    }

    dwStatus = MYDBG_SUCCESS;

cleanup:
    if (NULL != szCertSubjectName)
    {
        HeapFree(GetProcessHeap(), 0, szCertSubjectName);
        szCertSubjectName = NULL;
    }

    if (NULL != pRemoteCertContext)
    {
        CertFreeCertificateContext(pRemoteCertContext);
        pRemoteCertContext = NULL;
    }

    return dwStatus;
}

DWORD
ManualServerCertValidation(
    IN     PSTR        pszTargetName,
    IN     DWORD       dwCertFlags,
    IN     SOCKET      Socket,
    IN     PCredHandle phCreds,
    IN     PCtxtHandle phContext)
{
    DWORD          dwStatus = MYDBG_ERROR_ERROR;
    PCCERT_CONTEXT pRemoteCertContext = NULL;

    // Manual Server Cert Verification
    // Not called when:
    // - Server cert validation is turned off (g_fNoSrvCertChk)
    // - Auto server validation is turned on (g_fAutoServerCheck)

    if (g_fQryCtxtSerializedRemoteCertInProc ||
        g_fQryCtxtSerializedRemoteCert)
    {
        if (g_fQryCtxtSerializedRemoteCertInProc || g_fQryCtxtSerializedRemoteCert)
        {
            HRESULT hr = QueryAndDeserializeRemoteCertContext(
                phContext,
                g_fQryCtxtSerializedRemoteCert,
                &pRemoteCertContext);
            if (FAILED(hr))
            {
                printf("- Error 0x%x from QueryAndDeserializeRemoteCertContext!\n", hr);
                dwStatus = (DWORD)hr;
                goto cleanup;
            }
        }
        else
        {
            // User Mode:
            // - Call QContextA to get server cert context
            // -

            // Get server's certificate.
            //dwStatus = QueryContextAttributes(
             //   phContext,
             //   SECPKG_ATTR_REMOTE_CERT_CONTEXT,
             //   (PVOID)&pRemoteCertContext);
            if (SEC_E_OK != dwStatus)
            {
                printf("- Error (user mode) 0x%x querying remote certificate!\n", dwStatus);
                goto cleanup;
            }
        }

        // Display server certificate chain.
        DisplayCertChain(pRemoteCertContext, FALSE);

        // Check OCSP?
        if (g_fCheckOcsp)
        {
            CRYPT_DATA_BLOB blob;
            DWORD dwProp = 0;
            ULONG cbOCSP = 0;
            PBYTE pOCSP = NULL;
           printf("Checking OCSP\n");

            while ((dwProp = CertEnumCertificateContextProperties(pRemoteCertContext, dwProp) != 0))
            {
                printf("Property 0x%x found\n", dwProp);
            }
            if (CertGetCertificateContextProperty(pRemoteCertContext,
                CERT_OCSP_RESPONSE_PROP_ID,
                NULL,
                &cbOCSP
            ))
            {
                if (0 != cbOCSP)
                {
                    pOCSP = (PBYTE)DbglibLocalAlloc(cbOCSP);
                    if (!pOCSP)
                    {
                        dwStatus = MYDBG_ERROR_OUTOFMEMORY;
                        printf("- Error allocating memory for OCSP Creds\n");
                        goto cleanup;
                    }
                    if (!CertGetCertificateContextProperty(pRemoteCertContext,
                        CERT_OCSP_RESPONSE_PROP_ID,
                        pOCSP,
                        &cbOCSP))
                    {
                        dwStatus = MYDBG_ERROR_ERROR;
                        printf("- Couldn't get OCSP response into buffer, would be SEC_E_UNKNOWN CREDENTIALS\n");
                        DbglibLocalFree(pOCSP);
                        pOCSP = NULL;
                        goto cleanup;
                    }
                    printf("Property 0x%x found\n", CERT_OCSP_RESPONSE_PROP_ID);
                    printf("Length of ocspresponse 0x%x \n", cbOCSP);

                    blob.pbData = pOCSP;
                    blob.cbData = cbOCSP;

                    DecodeOCSPStaplingInfo(&blob);

                    //free OCSP buffer
                    if (NULL != pOCSP)
                    {
                        DbglibLocalFree(pOCSP);
                        pOCSP = NULL;
                    }
                }
            } //CertGetCertificateContextProperty
            else
            {
                dwStatus = GetLastError();
                printf("- Tried to query for OCSP credentials, but none were found: Error 0x%x\n", dwStatus);
                dwStatus = MYDBG_ERROR_ERROR;
                goto cleanup;
            }
        }
        // Attempt to validate server certificate.
        if (!g_fWinVerifyTrust)
        {
            // Use CertGetCertificateChain
            dwStatus = VerifyServerCertificate(
                pRemoteCertContext,
                pszTargetName,
                0);
        }
        else
        {
            // Use WinVerifyTrust
            dwStatus = VerifyServerCertificateWVT(
                pRemoteCertContext,
                pszTargetName,
                0);
        }

        // check if server cert validation was successful
        if (SEC_E_OK != dwStatus)
        {
            if (!g_fCheckOcsp)
            {
                printf("- Error validating server cert manually\n");
                if (g_fSendAlert)
                {
                    dwStatus = BuildAndSendAlert(
                        Socket,
                        phCreds,
                        phContext,
                        dwStatus);
                    if (SEC_E_OK != dwStatus)
                    {
                        printf("- Error sending alert!\n");
                    }
                    goto cleanup;

                }
                // NON-FATAL: even if cert doesn't validate, set success
                dwStatus = MYDBG_SUCCESS;
            }
            else
            {
                //we WANT to fail if validation fails for OCSP
                printf("- Error validating server cert manually - Required for OCSP\n");
                dwStatus = MYDBG_ERROR_ERROR;
            }
        }
    } 
    else
    {
        // Kernel Mode
        //
        printf("- Kernel Mode missing manual server cert validation!\n");
    }

cleanup:
    // free the server cert context
    if (pRemoteCertContext)
    {
        CertFreeCertificateContext(pRemoteCertContext);
        pRemoteCertContext = NULL;
    }

    return dwStatus;
}
/*########### SERVER CERTIFICATE VALIDATION ENDS ####################*/

/*########### CLIENT CERTIFICATE SELECTION START ####################*/

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
    SchannelCred.v4.dwVersion = g_fUseSchCredentials ? SCH_CREDENTIALS_VERSION : SCHANNEL_CRED_VERSION;

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
    if (dwClientAuthMode == CLIENT_AUTH_AUTOMATIC)
    {
        // schannel will pick client cert automatically
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_USE_DEFAULT_CREDS;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_USE_DEFAULT_CREDS;
        }
        printf("- Let Schannel pick client cert automatically\n");
    }
    else
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
        else if (CLIENT_AUTH_MANUAL == dwClientAuthMode)
        {
            printf("- no username, no creds, Schannel auto picks?\n");
        }

        //===================================================================
        // Call CryptAcquireContext
        // HACK for repro'ing the wireless scenario: should put more thought
        //===================================================================
        if (CLIENT_AUTH_CALL_CAQ == dwClientAuthMode)
        {
            DWORD      cbData = 0;
            HCRYPTPROV hProv2 = 0;
            DWORD      cbProvHandle = 0;

            g_pDupCertContext = CertDuplicateCertificateContext(pCertContext);
            if (NULL == g_pDupCertContext)
            {
                dwStatus = GetLastError();
                printf("- CertDuplicateCertificateContext failed: 0x%x!\n", dwStatus);
                goto cleanup;
            }

            if (!CertGetCertificateContextProperty(
                pCertContext,
                CERT_KEY_PROV_INFO_PROP_ID,
                NULL,
                &cbData)
                )
            {
                dwStatus = GetLastError();
                printf("- CertGetCertificateContextProperty(1) failed: 0x%x!\n", dwStatus);
                goto cleanup;
            }

            pCryptKeyProvInfo = (PCRYPT_KEY_PROV_INFO)DbglibLocalAlloc(cbData);
            if (NULL == pCryptKeyProvInfo)
            {
                printf("- Out of memory!\n");
                dwStatus = WEBCLI_ERROR_ERROR;
                goto cleanup;
            }

            if (!CertGetCertificateContextProperty(
                pCertContext,
                CERT_KEY_PROV_INFO_PROP_ID,
                pCryptKeyProvInfo,
                &cbData)
                )
            {
                dwStatus = GetLastError();
                printf("- CertGetCertificateContextProperty(2) failed: 0x%x!\n", dwStatus);
                goto cleanup;
            }

            // finally call CAQ
            printf("- %ws, %ws, 0x%x, 0x%x\n",
                pCryptKeyProvInfo->pwszContainerName,
                pCryptKeyProvInfo->pwszProvName,
                pCryptKeyProvInfo->dwProvType,
                pCryptKeyProvInfo->dwFlags
            );

            if (!CryptAcquireContextW(
                &g_hProv,
                pCryptKeyProvInfo->pwszContainerName,
                pCryptKeyProvInfo->pwszProvName,
                pCryptKeyProvInfo->dwProvType,
                (pCryptKeyProvInfo->dwFlags & ~CERT_SET_KEY_PROV_HANDLE_PROP_ID) |
                CRYPT_SILENT)
                )
            {
                dwStatus = GetLastError();
                printf("- CryptAcquireContext failed: 0x%x!\n", dwStatus);
                goto cleanup;
            }

            if (!CertSetCertificateContextProperty(
                pCertContext,
                CERT_KEY_PROV_HANDLE_PROP_ID,
                CERT_STORE_NO_CRYPT_RELEASE_FLAG,
                (VOID*)(g_hProv)))
            {
                dwStatus = GetLastError();
                printf("- CertSetCertificateContextProperty failed: 0x%x\n", dwStatus);
                goto cleanup;
            }

            // call again to make sure it passes
            cbProvHandle = sizeof(HCRYPTPROV);

            if (!CertGetCertificateContextProperty(
                pCertContext,
                CERT_KEY_PROV_HANDLE_PROP_ID,
                (PVOID)&hProv2,
                &cbProvHandle)
                )
            {
                dwStatus = GetLastError();
                printf("- CertGetCertificateContextProperty(3) FAILED: 0x%x!\n", dwStatus);
                goto cleanup;
            }

        }
        //===================================================================
        // Put the certificate in a memory store and use that instead
        //===================================================================
        if (CLIENT_AUTH_MEMORY_STORE == dwClientAuthMode && pszPfxPath != NULL)
        {
            // open memory store
            if (hMemoryStore = CertOpenStore(
                CERT_STORE_PROV_MEMORY,    // Memory store
                0,                         // Encoding type
                                           // not used with a memory store
                0,                         // Use the default provider
                0,                         // No flags
                NULL)                      // Not needed
                )
            {
                printf("- Opened memory store successfully.\n");
            }
            else
            {
                dwStatus = GetLastError();
                printf("- Opening memory store FAILED!\n");
                goto cleanup;
            }

            // get the certificate chain and add to memory store
            {
                PCCERT_CHAIN_CONTEXT pCertChain = NULL;
                CERT_CHAIN_PARA      ChainPara = { 0 };
                UINT                 i = 0;
                LPSTR                rgszUsages[1] = {
                                         (LPSTR)szOID_PKIX_KP_CLIENT_AUTH };

                ZeroMemory(&ChainPara, sizeof(ChainPara));
                ChainPara.cbSize = sizeof(ChainPara);
                ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
                ChainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
                ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

                if (!CertGetCertificateChain(
                    NULL,
                    pCertContext,
                    NULL,
                    NULL,
                    &ChainPara,
                    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                    NULL,
                    &pCertChain)
                    )
                {
                    if (NULL == pCertChain)
                    {
                        dwStatus = GetLastError();
                        printf("- Fetching client chain FAILED!\n");
                        goto cleanup;
                    }
                }
                else
                {
                    printf("- Client cert chain fetched.\n");
                }

                printf("- No of chains is %i and elements is %i\n",
                    pCertChain->cChain,
                    pCertChain->rgpChain[0]->cElement);

                // Add certificates from the "MY" store to the memory store.
                // remove them from "MY" store
                for (i = 0; i < pCertChain->rgpChain[0]->cElement; i++)
                {
                    if (CertAddCertificateContextToStore(
                        hMemoryStore,                  // Store handle
                        pCertChain->rgpChain[0]->rgpElement[i]->pCertContext,
                        CERT_STORE_ADD_USE_EXISTING,
                        NULL)
                        )
                    {
                        printf("- Adding cert %i to memory store succeeded.\n",
                            i);
                    }
                    else
                    {
                        printf("- Adding cert to memory store FAILED!\n");
                        dwStatus = GetLastError();
                        goto cleanup;
                    }

                    // remove from my store. Dont remote the SuperCert though.
                    if (i < (pCertChain->rgpChain[0]->cElement - 1))
                    {
                        if (!CertDeleteCertificateFromStore(
                            pCertChain->rgpChain[0]->rgpElement[i]->pCertContext)
                            )
                        {
                            printf("- Deleting cert from store FAILED!\n");
                        }
                    }

                    pCertChain->rgpChain[0]->rgpElement[i]->pCertContext = NULL;

                }

                if (pCertChain)
                {
                    CertFreeCertificateChain(pCertChain);
                    pCertChain = NULL;
                }
            }

            // free cert context
            if (pCertContext)
            {
                CertFreeCertificateContext(pCertContext);
                pCertContext = NULL;
            }

            // get new cert context from the memory store
            pCertContext = CertFindCertificateInStore(
                hMemoryStore,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_STR_A,
                pszUserName,
                NULL);
            if (NULL == pCertContext)
            {
                dwStatus = GetLastError();
                printf("- CertFindCertificateInStore FAILED for memory store 0x%x!\n", dwStatus);
                goto cleanup;
            }
            else
            {
                printf("- Found client cert in memory store.\n");
            }

        } // if(g_fUseMeoryStore)

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
        SchannelCred.v4.grbitEnabledProtocols = g_dwProtocol;

        if (g_cSupportedAlgs)
        {
            SchannelCred.v4.cSupportedAlgs = g_cSupportedAlgs;
            SchannelCred.v4.palgSupportedAlgs = g_rgbSupportedAlgs;
        }
    }
    else
    {
        if (SchannelCred.v5.cTlsParameters > 0)
        {
            // The last parameter in the blacklist will hold the protocol version(s) blacklisted.
            SchannelCred.v5.pTlsParameters[SchannelCred.v5.cTlsParameters - 1].grbitDisabledProtocols = g_dwDisabledProtocols;
        }
        else
        {
            tlsParameters.grbitDisabledProtocols = g_dwDisabledProtocols;
            SchannelCred.v5.pTlsParameters = &tlsParameters;
            SchannelCred.v5.cTlsParameters = 1;
        }
    }


    if ((!g_fAutoServerCheck || g_fNoSrvCertCheck) &&
        !g_fAchReqDeferredCredValidation &&
        !g_fIscReqDeferredCredValidation)
    {
        // don't have Schannel validate server certificate
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        }
        //WEBCLI_SRVCERT_VALIDATION_MANUAL;
    }

    if (g_fAutoServerCheck && g_fNoSrvNameCheck)
    {
        // Schannel will not compare supplied server name
        // with subject name in server cert
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
        }
    }

    // add memory store flag
    if (CLIENT_AUTH_MEMORY_STORE == dwClientAuthMode)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_MEMORY_STORE_CERT;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_MEMORY_STORE_CERT;
        }
    }

    // if Schannel requires to send extra record
    // enable SCH_SEND_AUX_RECORD flag
    if (g_fSendExtraRecord == TRUE)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_SEND_AUX_RECORD;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_SEND_AUX_RECORD;
        }
    }

    if (g_fUseSecureCiphers)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_USE_STRONG_CRYPTO;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_USE_STRONG_CRYPTO;
        }
    }

    if (g_fAllowNullEncryptionCiphers)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
        }
    }

    if (g_fAchReqDeferredCredValidation)
    {
        if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
        {
            SchannelCred.v4.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
        }
        else
        {
            SchannelCred.v5.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
        }
    }

    //
    // Create an SSPI credential.
    //
    dwStatus = AcquireCredentialsHandleA(
            NULL,                   // Name of principal
            g_pszTLSPackageName,    // Name of package
            SECPKG_CRED_OUTBOUND,   // Flags indicating use
            NULL,                   // Pointer to logon ID
            (dwClientAuthMode == CLIENT_AUTH_PICKLED_CRED) ?
            &ClientAuthID :
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

// CRYPT_ALGORITHM_IDENTIFIER to eTlsSignatureAlgorithm and eTlsHashAlgorithm Map
// Add new mapping for new certs added to the tests
static const struct
{
    LPSTR pszAlgoID;
    BYTE  bTlsSignatureAlgo;
    BYTE  bTlsHashAlgo;
}   CryptAlgoIDToTlsAlgoMap[] = {
    { (LPSTR)"1.2.840.10045.4.3.2", TlsSignatureAlgorithm_Ecdsa, TlsHashAlgorithm_Sha256}, //ECDSAEcc256Cli: sha256ecdsa
    { (LPSTR)"1.2.840.10045.4.3.3", TlsSignatureAlgorithm_Ecdsa, TlsHashAlgorithm_Sha384}, //ECDSAEcc384Cli: sha384ecdsa
    { (LPSTR)"1.2.840.10045.4.3.4", TlsSignatureAlgorithm_Ecdsa, TlsHashAlgorithm_Sha512}, //ECDSAEcc521Cli: sha512ecdsa
    { (LPSTR)"1.2.840.10040.4.3", TlsSignatureAlgorithm_Dsa, TlsHashAlgorithm_Sha1}, //MsDssCliCert1024: sha1dsa
    { (LPSTR)"1.2.840.113549.1.1.5", TlsSignatureAlgorithm_Rsa, TlsHashAlgorithm_Sha1}, //MsEccRsaCliCert256, MsEccRsaCliCert384, MsEccRsaCliCert521, MsEccRsaCliCert1024 : sha1rsa
    { (LPSTR)"1.2.840.113549.1.1.4", TlsSignatureAlgorithm_Rsa, TlsHashAlgorithm_Md5}, //NSSECCCliCert256, NSSECCCliCert384, NSSECCCliCert521, NSSECCCliCertRSA : md5rsa
};

/*********************************************************************
 Get the TLS hash and signature algorithms corresponding to the
 CRYPT_ALGORITHM_IDENTIFIER from CryptAlgoIDToTlsAlgoMap[]
*********************************************************************/

DWORD
GetTlsAlgorithmForCryptID(
    IN     LPSTR pszOId)
{
    DWORD  dwSignatureAndHashAlgo = 0;
    int    i = 0;

    for (i = 0; i < _countof(CryptAlgoIDToTlsAlgoMap); i++)
    {
        if (_strcmpi(CryptAlgoIDToTlsAlgoMap[i].pszAlgoID, pszOId) == 0)
        {
            dwSignatureAndHashAlgo = (CryptAlgoIDToTlsAlgoMap[i].bTlsSignatureAlgo << 8) | CryptAlgoIDToTlsAlgoMap[i].bTlsHashAlgo;
            break;
        }
    }

    return dwSignatureAndHashAlgo;
}

/*********************************************************************
 Case: CLIENT_AUTH_PROGRAMATIC: Webclient selects client cert
 Automatically pick a client cert from system store and use it.
 Frees input phCreds if needed.
*********************************************************************/
DWORD
ProgrammaticClientCredentials(
    IN OUT CredHandle* phCreds,
    IN     CtxtHandle* phContext)
{
    DWORD                               dwStatus = WEBCLI_ERROR_ERROR;
    CredHandle                          hCreds = { 0 };
    SecPkgContext_IssuerListInfoEx      IssuerListInfo = { 0 };
    PCCERT_CHAIN_CONTEXT                pChainContext = NULL;
    CERT_CHAIN_FIND_BY_ISSUER_PARA      FindByIssuerPara = { 0 };
    PCCERT_CONTEXT                      pCertContext = { 0 };
    TimeStamp                           tsExpiry = { 0 };
    union
    {
        SCHANNEL_CRED v4;
        SCH_CREDENTIALS v5;
    } SchannelCred = { 0 };

    // cred version
    SchannelCred.v4.dwVersion = g_fUseSchCredentials ? SCH_CREDENTIALS_VERSION : SCHANNEL_CRED_VERSION;
    HCERTSTORE                          hMyCertStore = NULL;
    SecPkgContext_SupportedSignatures   SupportedSignaturesList = { 0 };
    BOOL                                fIsTls1_2 = FALSE;
    BOOL                                fAlgoMatchFound = FALSE;
    DWORD                               dwTlsSignAndHashAlgo = 0;
    int                                 i = 0;
    LPTSTR                              certSubjectName = NULL;
    DWORD                               cCertSubjectName = 0;
    SCHANNEL_CERT_HASH                  kModeCertHash = { sizeof(SCHANNEL_CERT_HASH), 0, 0, {0} };

    // Open the "MY" certificate store
    hMyCertStore = CertOpenSystemStore(0, "MY");

    if (!hMyCertStore)
    {
        dwStatus = GetLastError();
        printf("- Error 0x%x returned by CertOpenSystemStore!\n", dwStatus);
        goto cleanup;
    }

    //
    // Read list of trusted issuers from schannel.
    //

    dwStatus = QueryContextAttributes(
        phContext,
       SECPKG_ATTR_ISSUER_LIST_EX,
        (PVOID)&IssuerListInfo);

    if (dwStatus != SEC_E_OK)
    {
        printf("- Error 0x%x querying issuer list info!\n", dwStatus);
        goto cleanup;
    }

    printf("- QContextA(ISSUER_LIST_EX) succeeded\n");

    //
    // Enumerate the client certificates.
    //
    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

    pChainContext = NULL;

    //
    // Read list of supported signatures from schannel.
    //

    dwStatus = QueryContextAttributes(
            phContext,
            SECPKG_ATTR_SUPPORTED_SIGNATURES,
            (PVOID)&SupportedSignaturesList);

    // if SEC_E_OK, then we know its tls1.2
    if (dwStatus == SEC_E_OK)
    {
        fIsTls1_2 = TRUE;
    }

    // this qca not supported for < tls1.2
    else if (dwStatus != SEC_E_UNSUPPORTED_FUNCTION)
    {
        printf("- Error 0x%x querying supported signatures info!\n",
            dwStatus);
        goto cleanup;
    }

    printf("- QContextA(SUPPORTED_SIGNATURES) succeeded\n");

    while (TRUE)
    {
        // Find a certificate chain.
        pChainContext = CertFindChainInStore(
            hMyCertStore,
            X509_ASN_ENCODING,
            0,
            CERT_CHAIN_FIND_BY_ISSUER,
            &FindByIssuerPara,
            pChainContext);

        if (pChainContext == NULL)
        {
            dwStatus = GetLastError();
            printf("- Error 0x%x finding cert chain!\n",
                dwStatus);
            break;
        }

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Log the subject of the certificate we are considering
        cCertSubjectName = CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, NULL, 0);

        certSubjectName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, cCertSubjectName * sizeof(TCHAR));
        if (certSubjectName != NULL)
        {
            CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject,
                CERT_SIMPLE_NAME_STR, certSubjectName, cCertSubjectName);
            printf("- Checking certificate: %s\n", certSubjectName);

            HeapFree(GetProcessHeap(), 0, certSubjectName);
        }

        // For TLS 1.2 check that the certificate chain's signature/hash are supported
        if (fIsTls1_2 == TRUE)
        {
            dwTlsSignAndHashAlgo = GetTlsAlgorithmForCryptID(pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);

            fAlgoMatchFound = FALSE;

            if (dwTlsSignAndHashAlgo != 0)
            {
                for (i = 0; i < SupportedSignaturesList.cSignatureAndHashAlgorithms; i++)
                {
                    // hash and signature algorithms match
                    if ((dwTlsSignAndHashAlgo ^ SupportedSignaturesList.pSignatureAndHashAlgorithms[i]) == 0)
                    {
                        fAlgoMatchFound = TRUE;
                        printf("- Matching Certificate Found. CRYPT_ALGORITHM_IDENTIFIER: %s Hash Algorithm Enum: %d Signature Algorith Enum: %d\n",
                            pCertContext->pCertInfo->SignatureAlgorithm.pszObjId, dwTlsSignAndHashAlgo & 0xff, dwTlsSignAndHashAlgo >> 8);
                        break;
                    }
                }
            }
            else
            {
                printf("- Unknown Signature Hash Algorithm for cert with CRYPT_ALGORITHM_IDENTIFIER: %s\n",
                    pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);
            }

            // skip this cert if a signature hash algorithm match is not found
            if (fAlgoMatchFound != TRUE)
            {
                continue;
            }
        }

        //
        // Skip ECC certificates for < TLS protocols
        //

        if (pCertContext->pCertInfo != NULL)
        {
            if (0 == _strcmpi(
                pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                szOID_ECC_PUBLIC_KEY))
            {
                continue;
            }
        }

        printf("- Certificate chain found.\n");

        // Create schannel credential.
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

        // if Schannel requires to send extra record
        // enable SCH_SEND_AUX_RECORD flag
        if (g_fSendExtraRecord == TRUE)
        {
            if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
            {
                SchannelCred.v4.dwFlags |= SCH_SEND_AUX_RECORD;
            }
            else
            {
                SchannelCred.v5.dwFlags |= SCH_SEND_AUX_RECORD;
            }
        }

        if (g_fUseSecureCiphers)
        {
            if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
            {
                SchannelCred.v4.dwFlags |= SCH_USE_STRONG_CRYPTO;
            }
            else
            {
                SchannelCred.v5.dwFlags |= SCH_USE_STRONG_CRYPTO;
            }
        }

        if (g_fAllowNullEncryptionCiphers)
        {
            if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
            {
                SchannelCred.v4.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
            }
            else
            {
                SchannelCred.v5.dwFlags |= SCH_ALLOW_NULL_ENCRYPTION;
            }
        }

        if (g_fAchReqDeferredCredValidation)
        {
            if (SchannelCred.v4.dwVersion == SCHANNEL_CRED_VERSION)
            {
                SchannelCred.v4.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
            }
            else
            {
                SchannelCred.v5.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
            }
        }

        dwStatus = AcquireCredentialsHandle(
                NULL,                   // Name of principal
                g_pszTLSPackageName,    // Name of package
                SECPKG_CRED_OUTBOUND,   // Flags indicating use
                NULL,                   // Pointer to logon ID
                &SchannelCred,          // Package specific data
                NULL,                   // Pointer to GetKey() func
                NULL,                   // Value to pass to GetKey()
                &hCreds,                // (out) Cred Handle
                &tsExpiry);             // (out) Lifetime (optional)
 

        if (dwStatus != SEC_E_OK)
        {
            printf("- Error 0x%x returned by AcquireCredentialsHandle!\n", dwStatus);
            continue;
        }

        printf("- New schannel credential created.\n");

        // Destroy the old credentials.
        FreeCredentialsHandle(phCreds);

        *phCreds = hCreds;

        break;
    }

cleanup:
    if (pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    // Close "MY" certificate store.
    if (hMyCertStore)
    {
        CertCloseStore(hMyCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
    }

    return dwStatus;
} // ProgrammaticClientCredentials()

/*########### CLIENT CERTIFICATE SELECTION END #####################*/



/*********************************************************************
 // Prints output from EnumerateSecurityPackages
*********************************************************************/
void
PrintSecPkgsInfo(CtxtHandle* phContext)
{
    DWORD         dwStatus = WEBCLI_ERROR_ERROR;
    ULONG         cPackages = 0;
    PSecPkgInfoW  pwPackages = NULL;
    PSecPkgInfo   pPackages = NULL;

    dwStatus = EnumerateSecurityPackages(&cPackages, &pPackages);

    if (FAILED(dwStatus))
    {
        printf("- Error calling EnumerateSecurityPackages!\n");
        goto cleanup;
    }

    // print the info
    if (NT_SUCCESS(dwStatus))
    {
        USHORT i;
        printf("- Printing the SecPkgInfo structures:\n");
        for (i = 0; i < cPackages; i++)
        {
            printf("%d. %s\n"
                "    Comment: %s\n"
                "    fCapabilities: 0x%08x\n"
                "    wVersion:      %d\n"
                "    wRPCID:        %d\n"
                "    cbMaxToken:    %d\n",
                i + 1,
                pPackages[i].Name,
                pPackages[i].Comment,
                pPackages[i].fCapabilities,
                pPackages[i].wVersion,
                pPackages[i].wRPCID,
                pPackages[i].cbMaxToken);
        }
    }

cleanup:
    return;
} // PrintSecPkgsInfo()

DWORD
QueryContextBufferSizes(IN PCtxtHandle phContext)
{
    DWORD  dwStatus = MYDBG_ERROR_ERROR;

    //
    // Read stream or connection encryption properties.
    //

    if (!g_fConnectionMode || g_fNoRecordLayer)
    {   // stream mode

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
    } // if(!ConnectionMode)

    else
    {   // connection mode
          //user mode
        dwStatus = QueryContextAttributes(
             phContext,
             SECPKG_ATTR_SIZES,
             &pvSizesConnection);

        if (dwStatus != SEC_E_OK)
        {
            printf("- Error 0x%x reading SECPKG_ATTR_SIZES.\n", dwStatus);
            return dwStatus;
        }

        printf("- MaxToken: %d, SecurityTrailer: %d, MaxSignature: %d.\n",
            pvSizesConnection.cbMaxToken,
            pvSizesConnection.cbSecurityTrailer,
            pvSizesConnection.cbMaxSignature);
    }

    return dwStatus;
}

//
// Routine Description:
//    Finds, loads, and initializes the schannel security package
//
// Return Value:
//    Returns SEC_E_OK is successful; otherwise errorcode is returned.
//
DWORD InitPackage(DWORD* pcbMaxMessage)
{
    DWORD                    dwStatus = MYDBG_ERROR_ERROR;
    PSecPkgInfo              pkgInfo = NULL;
    PSecurityFunctionTable   pFuncs = NULL;
    PCHAR                    pszPackage = (PCHAR)"Schannel";

    pFuncs = InitSecurityInterface();
    if (pFuncs == NULL)
    {
        printf("- Error calling InitSecurityInterface\n");
        goto cleanup;
    }

    //
    // Query package information
    //
    dwStatus = pFuncs->QuerySecurityPackageInfo(pszPackage, &pkgInfo);
    if (FAILED(dwStatus))
    {
        printf("- Error calling QuerySecurityPackageInfo!\n");
        goto cleanup;
    }
    *pcbMaxMessage = pkgInfo->cbMaxToken;

cleanup:

    if (pkgInfo)
    {
        pFuncs->FreeContextBuffer(pkgInfo);
    }

    return dwStatus;
}

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

    contentsLength = g_pszGeContentsVerify == NULL ? 0 : strlen(g_pszGeContentsVerify) + sizeof(ANSI_NULL);

    if (g_dwGeExtensionTypeVerify != extensionType ||
        contentsLength != extensionSize)
    {
        goto Cleanup;
    }

    if (g_pszGeContentsVerify == NULL)
    {
        fReceivedExpectedGenericExtension = TRUE;
    }
    else
    {
        fReceivedExpectedGenericExtension = !memcmp(g_pszGeContentsVerify, pbGenericTlsExtensions, contentsLength);
    }

Cleanup:

    return fReceivedExpectedGenericExtension;
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

void ResetGlobals()
{
    // User options.
    g_pszTargetName = NULL;
    g_pszUserName = NULL;
    g_pszPfxPath = NULL;
    iPortNumber = 443;
    g_IoBufSize = IO_BUFFER_SIZE;
    pszFileName = (LPSTR)"default.htm";
    g_dwIterationCount = 1;
    fUseProxy = FALSE;
    g_fSaveReceivedFile = FALSE;
    pszReceivedFileName = (LPSTR)"received.bin";

    g_dwProtocol = 0;
    g_dwNegotiatedProtocol = 0;
    g_dwDisabledProtocols = 0;
    g_fUseSchCredentials = FALSE;
    g_fAllowNullEncryptionCiphers = FALSE;

    g_dwMinCipherStrength = 0;
    g_dwMaxCipherStrength = 0;
    g_cSupportedAlgs = 0;
    g_hProv = 0;
    g_fNoRecordLayer = FALSE;
    g_pszServerSpeaksFirst = NULL;

    ClientContext = NULL;

    // Generic extensions.
    g_dwGeExtensionType = ULONG_MAX;
    g_dwGeHandshakeType = ULONG_MAX;
    g_pszGeContents = NULL;
    g_dwGeExtensionTypeVerify = ULONG_MAX;
    g_dwGeHandshakeTypeVerify = ULONG_MAX;
    g_pszGeContentsVerify = NULL;

    // server revocation option
    dwSrvCertRvcnOpt = 0;

    // the client certificate selection method
    dwClientAuthMode = CLIENT_AUTH_DEFAULT_MODE;

    g_fDowngrade = FALSE;

    // the below flag specifies ISC_REQ_MUTUAL_AUTH,
    // whereby Schannel automatically validates the server cert.
    g_fMutualAuth = FALSE;
    g_fManualCredValidation = FALSE;

    g_fSendAlert = FALSE;  // send alert
    g_fKeepAlive = FALSE;  // keep connection alive
    g_fReconnect = FALSE;  // reconnection scenario
    g_fRenegotiate = FALSE;  // renegotiation scenario
    g_fSendCloseNotify = FALSE;  // send close_notify
    g_fUseNewQOP = FALSE;  // generate alerts via EncryptMessage
    g_fConnectionMode = FALSE;  // Stream or Connection Mode
    g_fNonContiguousBuffers = FALSE; // Contiguous buffers
    g_fDisableReconnects = FALSE;  // Disable reconnects
    g_fPackageInfo = FALSE;  // print EnumerateSecurityPackage
    g_fUseSmallBuffer = FALSE;
    g_fAllocateMemory = FALSE;  // SSPI app allocates it's own memory
    g_fSendExtraRecord = FALSE;     // Flag to check if schannel needs to fragment record in 1 and (n-1) bytes
    g_fVerifyExtraRecord = FALSE;   // Flag to check if the peer has sent extra record
    g_fExtraDataReceived = FALSE;   // Flag to check if extra data is received
    g_fMeasureAlertRespTime = FALSE;    //Flag to check if we need to measure the response time of an ALERT
    g_dwMaxToken = 0;      // Maximum message size the package can handle
    g_dwSendRootCert = 0;      // Other Cred Flags (Send Root Cert)
    g_fIgnoreHttpError = FALSE;
    g_fIscReqDeferredCredValidation = FALSE; // Request ISC_REQ_DEFERRED_CRED_VALIDATION
    g_fAchReqDeferredCredValidation = FALSE; // Request SCH_CRED_DEFERRED_CRED_VALIDATION
    g_fNoPostHandshakeAuth = FALSE; // Don't send post_handshake_auth extension in TLS 1.3 Client Hello

    //
    // query context attributes
    //
    // both user and kernel mode
    g_fQryCtxtAll = FALSE;
    g_fQryCtxtConnInfo = FALSE;
    g_fQryCtxtSizes = FALSE;
    g_fQryCtxtCipherInfo = TRUE;  // QueryContextAttributes Cipher Info
    g_fQryCtxtSupportedSignatures = FALSE;
    g_fQryCtxtKeyingMaterialInproc = FALSE;
    g_fQryCtxtCertValidationResult = FALSE;
    g_fQryCtxtCertValidationResultInProc = FALSE;
    g_fQryCtxtSerializedRemoteCertInProc = FALSE;
    g_fQryCtxtSerializedRemoteCert = FALSE;

    // only user mode
    g_fQryCtxtIssrListEx = FALSE;  // QueryContextAttributes issuer list
    g_fQryCtxtRemoteCert = FALSE;
    g_fQryCtxtLocalCert = FALSE;
    g_fQryCtxtSessInfo = FALSE;
    g_fQryCtxtKeyInfo = FALSE;  // QueryContextAttributes key
    g_fQryCtxtProtoInfo = FALSE;  // QueryContextAttributes protocol
    g_fQryCtxtEapKeyBlock = FALSE;  // QueryContextAttributes NULL;
    g_fQryCtxtAppData = FALSE;
    g_fQryCtxtLifeSpan = FALSE;
    g_fQryCtxtNames = FALSE;
    g_fQryCtxtAuthority = FALSE;
    g_fQryCtxtKeyingMaterial = FALSE;

    // query credentials attributes
    g_fQueryAllCreds = FALSE;
    g_fQuerySuppAlgs = FALSE;
    g_fQueryCiphStrgths = FALSE;
    g_fQuerySuppProtocols = FALSE;
    g_fQueryCredNames = FALSE;

    // query and check values
    g_fQueryAndCheckReconnect = FALSE;
    g_dwReconnect = SSL_SESSION_RECONNECT;
    g_fQueryAndCheckCiphersuite = FALSE;
    g_dwCipherSuite = 0;
    g_fQueryAndCheckKeyType = FALSE;
    g_dwKeyType = 0;
    g_fQueryAndCheckMachineId = FALSE;
    g_dwMachineID = 0;
    g_CheckFlagExtendedError = FALSE;
    g_fSendZeroLengthApplicationData = FALSE;
    g_fAcceptZeroLengthApplicationData = FALSE;
    g_fVerifyReceiveCloseNotify = FALSE;
    g_fAllowEarlyDisconnect = FALSE;
    g_fEncryptAfterPostHandshake = FALSE;

    // set context attributes
    g_fSetCtxtAll = FALSE;
    g_fSetAppData = FALSE;
    g_fSetKeyingMaterialInfo = FALSE;
    g_fSetEAPProtocol = FALSE;
    g_dwSetEapPRF = 0;
    g_ftestEmptyMessage = FALSE;

    // Early (false) start
    g_fEarlyStartRequested = FALSE;
    g_fSetTlsClientEarlyStart = FALSE;
    g_fEarlyStartReady = FALSE;
    g_fEarlyStartGetSent = FALSE;

    g_fUseSecureCiphers = FALSE;
    g_pszTLSPackageName = (LPSTR)UNISP_NAME_A;

    // Expected error code
    g_dwExpectedISCError = ERROR_SUCCESS;

    return;
}

//++----------------------------------------------------------------------
//  NAME:  SetContextWrapper
//
//  DESC:  SetContextAttributes calls
//
//  ARGUMENTS:
//  - unsigned long ulAttribute 	: attribute to set
//  - PCredHandle				: context handle (useless here)
//
//  RETURNS:
//  - DWORD: status code
//
//  NOTE:
//--------------------------------------------------------------------++//
DWORD
SetContextWrapper(
    IN     DWORD       dwAttr,
    IN     PCtxtHandle phContext)
{
    DWORD                         tmp = 0xFFFFFF01;
    DWORD                         dwStatus = MYDBG_ERROR_ERROR;
    PVOID                         pBuffer = NULL;
    ULONG                         dwMemSize = 0;
    PSecPkgContext_SessionAppData pSessionData = NULL;
    PSecPkgContext_EapPrfInfo     pEapData = NULL;
    PVOID                         pMarshaledData = NULL;
    ULONG                         cbMarshaledData = 0;

    char szStr[100] = "This is some application data that the calling application can store with schannel for later use";

    PSecPkgContext_KeyingMaterialInfo pKeyingMaterialInfo = NULL;

    const char szAppContext[] = "This is application context data";
    const char szLabel[] = "EXPORTER: teap session key seed";

    // figure out how much memory to allocate
    // user mode attributes
    switch (dwAttr)
    {
    case SECPKG_ATTR_APP_DATA:
        dwMemSize = sizeof(SecPkgContext_SessionAppData);
        pSessionData = (PSecPkgContext_SessionAppData)DbglibLocalAlloc(dwMemSize);
        if (pSessionData == NULL)
        {
            dwStatus = MYDBG_ERROR_OUTOFMEMORY;
            goto cleanup;
        }
        pSessionData->cbAppData = (DWORD)(strlen(szStr));
        pSessionData->pbAppData = (PBYTE)szStr;
        pBuffer = pSessionData;
        break;

    case SECPKG_ATTR_EAP_PRF_INFO:
        dwMemSize = sizeof(SecPkgContext_EapPrfInfo);
        pEapData = (PSecPkgContext_EapPrfInfo)DbglibLocalAlloc(dwMemSize);
        if (pEapData == NULL)
        {
            dwStatus = MYDBG_ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        pEapData->cbPrfData = sizeof(DWORD);
        pEapData->pbPrfData = (PBYTE)&g_dwSetEapPRF;
        pEapData->dwVersion = 0;
        pBuffer = pEapData;
        break;

    case SECPKG_ATTR_KEYING_MATERIAL_INFO:
        dwMemSize = sizeof(SecPkgContext_KeyingMaterialInfo);
        pKeyingMaterialInfo = (PSecPkgContext_KeyingMaterialInfo)DbglibLocalAlloc(dwMemSize);
        if (pKeyingMaterialInfo == NULL)
        {
            dwStatus = MYDBG_ERROR_OUTOFMEMORY;
            goto cleanup;
        }
        pKeyingMaterialInfo->cbLabel = sizeof(szLabel);
        pKeyingMaterialInfo->pszLabel = (LPSTR)szLabel;
        pKeyingMaterialInfo->cbContextValue = sizeof(szAppContext);
        pKeyingMaterialInfo->pbContextValue = (PBYTE)szAppContext;
        pKeyingMaterialInfo->cbKeyingMaterial = KEYING_MATERIAL_LENGTH;
        pBuffer = pKeyingMaterialInfo;
        break;

    default:
        printf("- Unknown context attribute!\n");
        goto cleanup;
        break;
    }

    dwStatus = SetContextAttributes(
            phContext,
            dwAttr,
            pBuffer,
            dwMemSize);

    printf("- Returned 0x%x\n", dwStatus);

    if (SEC_E_OK != dwStatus)
    {
        printf("- Error 0x%x Setting Context Attribute!\n", dwStatus);
    }

cleanup:

    if (pBuffer)
    {
        DbglibLocalFree(pBuffer);
    }
    return dwStatus;
}

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
    if (g_fCompatCliMode)
    {
        strcpy_s(g_pszNegotiatedProtocol, 256, szString);
    }

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

    // check if extra record is expected from peer
    if (g_fVerifyExtraRecord && !g_fConnectionMode)
    {
        if ((pConnectionInfo->dwProtocol != SP_PROT_TLS1_0_CLIENT && pConnectionInfo->dwProtocol != SP_PROT_SSL3_CLIENT) ||
            (pConnectionInfo->aiCipher != CALG_3DES && pConnectionInfo->aiCipher != CALG_AES_128 && pConnectionInfo->aiCipher != CALG_AES_256))
        {
            g_fVerifyExtraRecord = FALSE;
            printf(" No need to verify extra record.\n");
        }
    }
    else if (g_fConnectionMode)
    {
        g_fVerifyExtraRecord = FALSE;
        printf(" No need to verify extra record, it is connection mode.\n");
    }
} // DisplayConnectionInfo()

DWORD ReadHexString(
    __in const PCHAR pszHexString,
    __in WORD cbBufferSize,
    __out PBYTE pBuffer,
    __out PWORD pcbWritten)
{
    PBYTE pBufferIter = pBuffer;
    PCHAR pHexStringIter = pszHexString;
    const DWORD maxHexString = cbBufferSize * 2;    // Two characters per byte.
    DWORD hexStringLen = 0;
    int value = 0;

    if (cbBufferSize == 0 || pBuffer == NULL || pcbWritten == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *pcbWritten = 0;
    hexStringLen = strnlen_s(pszHexString, maxHexString + 1);   // Allow an extra BYTE for the terminating NUL.
    if (hexStringLen == 0 || (hexStringLen % 2) != 0 || hexStringLen > maxHexString)
    {
        printf("Expected hex string: 2 hex digits per byte, up to %d digits\n", maxHexString);
        return ERROR_INVALID_PARAMETER;
    }

    for (; pHexStringIter < pszHexString + hexStringLen; pHexStringIter += 2, ++pBufferIter)
    {
        // Convert one byte at a time.
        if (1 != sscanf_s(pHexStringIter, "%2x", &value))
        {
            printf("Expected hex string: 2 hex digits per byte, up to %d digits\n", maxHexString);
            return ERROR_INVALID_PARAMETER;
        }
        *pBufferIter = (BYTE)value;
    }

    *pcbWritten = hexStringLen / 2;
    return ERROR_SUCCESS;
}

DWORD
QuicEncrypt(
    _In_ PQUIC_KEYS pQuicKey,
    _In_ BOOLEAN fServer,
    _Inout_ PSecBuffer pData)
{
    DWORD dwError = ERROR_SUCCESS;
    BYTE tempBuffer[MAX_TLS_RECORD_PLAINTEXT_SIZE + HeaderAndTagSize] = { 0 };
    PBYTE pbTempBuffer = (PBYTE)&tempBuffer;
    DWORD cbTempBuffer = MAX_TLS_RECORD_PLAINTEXT_SIZE + HeaderAndTagSize;
    DWORD cbResult = 0;

    if (pQuicKey == NULL ||
        pData == NULL ||
        pData->cbBuffer > MAX_TLS_RECORD_PLAINTEXT_SIZE)
    {
        dwError = (DWORD)SEC_E_INVALID_PARAMETER;
        goto cleanup;
    }

    // Do Encryption
    dwError = Tls13EncryptPacket(
        fServer ? pQuicKey->hServerWriteKey : pQuicKey->hClientWriteKey,
        fServer ? pQuicKey->rgServerIV : pQuicKey->rgClientIV,
        fServer ? pQuicKey->cbServerIV : pQuicKey->cbClientIV,
        (PBYTE)pData->pvBuffer,
        pData->cbBuffer,
        pbTempBuffer,
        cbTempBuffer,
        &cbResult,
        fServer ? pQuicKey->ServerSequenceNumber : pQuicKey->ClientSequenceNumber);
    if (dwError != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    pData->cbBuffer = cbResult;
    RtlCopyMemory(pData->pvBuffer, pbTempBuffer, pData->cbBuffer);

    if (fServer)
    {
        pQuicKey->ServerSequenceNumber++;
    }
    else
    {
        pQuicKey->ClientSequenceNumber++;
    }

cleanup:

    return dwError;
}

VOID
FreeOutputBuffer(
    _In_ PSecBuffer pOutBuffer)
{

    if (pOutBuffer == NULL)
    {
        return;
    }

    if (g_fAllocateMemory)
    {
        DbglibLocalFree(pOutBuffer->pvBuffer);
    }
    else
    {
        //pfnFreeContextBuffer(pOutBuffer->pvBuffer);
    }
    pOutBuffer->pvBuffer = NULL;

    // This function does not zero cbBuffer by-design as the value is needed when testing -allocSmall, where cbBuffer would contain the
    // required size of the buffer after the first ISC/ASC and zeroing it out would cause AllocateOutputBuffer to keep allocating
    // 1-byte buffers, resulting in an infinite loop.
}

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
QuicDecrypt(
    _In_ PQUIC_KEYS pQuicKey,
    _In_ BOOLEAN fServer,
    _Inout_ PSecBuffer pData)
{
    DWORD dwError = ERROR_SUCCESS;
    BYTE tempBuffer[MAX_TLS_RECORD_PLAINTEXT_SIZE] = { 0 };
    PBYTE pbTempBuffer = (PBYTE)&tempBuffer;
    DWORD cbTempBuffer = MAX_TLS_RECORD_PLAINTEXT_SIZE;

    PBYTE pbInput = (PBYTE)pData->pvBuffer;
    DWORD cbInput = pData->cbBuffer;
    DWORD cbResult = 0;
    PBYTE pbOutput = (PBYTE)pData->pvBuffer;
    pData->cbBuffer = 0;

    if (pQuicKey == NULL ||
        pData == NULL ||
        pData->cbBuffer > MAX_TLS_RECORD_CIPHERTEXT_SIZE)
    {
        dwError = (DWORD)SEC_E_INVALID_PARAMETER;
        goto cleanup;
    }

    do
    {
        if (cbInput < TLS_RECORD_HEADER)
        {
            dwError = (DWORD)SEC_E_INTERNAL_ERROR;
            goto cleanup;
        }

        DWORD encryptedLength = COMBINETWOBYTES(pbInput[3], pbInput[4]) + TLS_RECORD_HEADER;

        dwError = Tls13DecryptPacket(
            fServer ? pQuicKey->hClientWriteKey : pQuicKey->hServerWriteKey,
            fServer ? pQuicKey->rgClientIV : pQuicKey->rgServerIV,
            fServer ? pQuicKey->cbClientIV : pQuicKey->cbServerIV,
            pbInput,
            encryptedLength,
            pbTempBuffer,
            cbTempBuffer,
            &cbResult,
            fServer ? pQuicKey->ClientSequenceNumber : pQuicKey->ServerSequenceNumber);
        if (dwError != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        if (fServer)
        {
            pQuicKey->ClientSequenceNumber++;
        }
        else
        {
            pQuicKey->ServerSequenceNumber++;
        }

        BOOLEAN fIsHandshakeMessage = SECBUFFER_DATA == pData->BufferType && HANDSHAKE_TRAFFIC == pbTempBuffer[cbResult - 1];
        RtlCopyMemory(pbOutput, pbTempBuffer, pData->BufferType == SECBUFFER_TOKEN || fIsHandshakeMessage ? --cbResult : cbResult);
        pbOutput += cbResult;
        pData->cbBuffer += cbResult;
        pbInput += encryptedLength;
        cbInput -= encryptedLength;

        if (fIsHandshakeMessage)
        {
            if (cbInput > 0)
            {
                // Put the extra data after our freshly decrypted data.
                RtlMoveMemory(pbOutput, pbInput, cbInput);
                pData->cbBuffer += cbInput;
            }
            dwError = (DWORD)SEC_I_RENEGOTIATE;
            break;
        }

    } while (cbInput > 0);

cleanup:

    return dwError;
}

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
        pIssuerCert  = NULL;
    }

} // DisplayCertChain()

DWORD
Tls13DecryptPacket(
    _In_ BCRYPT_KEY_HANDLE Key,
    _In_ PBYTE pbIV,
    _In_ DWORD cbIV,
    _In_reads_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ ULONGLONG SequenceNumber)
{
    WORD HeaderSize = TLS_RECORD_HEADER;
    WORD CiphertextLength = 0;
    WORD PlaintextLength = 0;
    DWORD cbResult = 0;
    // The nonce is only SSL_AES_GMC_NONCE_LENGTH (12) bytes long, but we want to ensure 
    // the last 8 bytes are aligned for ULONGLONG (the type of the record sequence number).
    ULONGLONG rgbNonce[2] = { 0 };
    PBYTE pNonce = (PBYTE)rgbNonce + sizeof(rgbNonce) - SSL_AES_GMC_NONCE_LENGTH;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo =
    {
        sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        pNonce,
        SSL_AES_GMC_NONCE_LENGTH,
        NULL,                               // pbAuthData
        0                                   // cbAuthData
    };
    SECURITY_STATUS Status = ERROR_SUCCESS;

    if (Key == NULL ||
        pbInput == NULL || pbOutput == NULL || pcbResult == NULL)
    {
        return (DWORD)NTE_INVALID_PARAMETER;
    }

    if (cbInput <= HeaderAndTagSize || cbInput > (DWORD)(MAX_TLS_RECORD_PLAINTEXT_SIZE + HeaderAndTagSize))
    {
        return (DWORD)NTE_BAD_DATA;
    }

    // Input and output buffers have to be either properly aligned or non-overlapping.
    if (pbInput + HeaderSize != pbOutput &&
        ((pbOutput >= pbInput && pbOutput < pbInput + cbInput) ||
            (pbInput >= pbOutput && pbInput < pbOutput + cbOutput)))
    {
        return (DWORD)NTE_BUFFERS_OVERLAP;
    }

    CiphertextLength = COMBINETWOBYTES(pbInput[3], pbInput[4]);
    if (CiphertextLength <= SSL_AES_GMC_AUTH_TAG_LENGTH || (DWORD)(CiphertextLength + HeaderSize) != cbInput)
    {
        return (DWORD)NTE_BAD_DATA;
    }

    PlaintextLength = CiphertextLength - SSL_AES_GMC_AUTH_TAG_LENGTH;

    if (cbOutput < PlaintextLength)
    {
        return (DWORD)NTE_BUFFER_TOO_SMALL;
    }

    AuthInfo.pbAuthData = pbInput;
    AuthInfo.cbAuthData = HeaderSize;
    AuthInfo.pbTag = pbInput + HeaderSize + PlaintextLength;
    AuthInfo.cbTag = SSL_AES_GMC_AUTH_TAG_LENGTH;

    // The per-record nonce for the AEAD construction is formed as follows:
    // 1.  The 64 - bit record sequence number is encoded in network byte
    //     order and padded to the left with zeros to iv_length.
    // 2.  The padded sequence number is XORed with the static
    //     client_write_iv or server_write_iv, depending on the role.
    CopyMemory(pNonce, pbIV, cbIV);
    rgbNonce[1] ^= htonll(SequenceNumber);
    Status = BCryptDecrypt(
        Key,
        pbInput + HeaderSize,
        PlaintextLength,
        &AuthInfo,
        NULL,               // pbIV
        0,                  // cbIV
        pbOutput,
        cbOutput,
        &cbResult,
        0);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    if (cbResult != PlaintextLength)
    {
        return (DWORD)NTE_DECRYPTION_FAILURE;
    }

    // Set the output values.
    *pcbResult = cbResult;
    return Status;
}

DWORD
Tls13EncryptPacket(
    _In_ BCRYPT_KEY_HANDLE Key,
    _In_ PBYTE pbIV,
    _In_ DWORD cbIV,
    _In_reads_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ ULONGLONG SequenceNumber)
{
    WORD HeaderSize = TLS_RECORD_HEADER;
    PBYTE pHeader = pbOutput;
    WORD CiphertextLength = (WORD)cbInput + SSL_AES_GMC_AUTH_TAG_LENGTH;
    DWORD RecordSize = 0;
    DWORD cbResult = 0;
    // The nonce is only SSL_AES_GMC_NONCE_LENGTH (12) bytes long, but we want to ensure 
    // the last 8 bytes are aligned for ULONGLONG (the type of the record sequence number).
    ULONGLONG rgbNonce[2] = { 0 };
    PBYTE pNonce = (PBYTE)rgbNonce + sizeof(rgbNonce) - SSL_AES_GMC_NONCE_LENGTH;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo =
    {
        sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        pNonce,
        SSL_AES_GMC_NONCE_LENGTH,
        NULL,                               // pbAuthData
        0                                   // cbAuthData
    };
    SECURITY_STATUS Status = ERROR_SUCCESS;

    if (Key == NULL || pbIV == NULL || cbIV == 0 ||
        pbInput == NULL || cbInput == 0 || cbInput > MAX_TLS_RECORD_PLAINTEXT_SIZE ||
        pbOutput == NULL || pcbResult == NULL)
    {
        return (DWORD)NTE_INVALID_PARAMETER;
    }

    RecordSize = HeaderSize + CiphertextLength;
    if (cbOutput < RecordSize)
    {
        return (DWORD)NTE_BUFFER_TOO_SMALL;
    }

    // Input and output buffers have to be either properly aligned or non-overlapping.
    if (pbOutput + HeaderSize != pbInput &&
        ((pbOutput >= pbInput && pbOutput < pbInput + cbInput) ||
            (pbInput >= pbOutput && pbInput < pbOutput + cbOutput)))
    {
        return (DWORD)NTE_BUFFERS_OVERLAP;
    }

    *pHeader++ = APPLICATION_TRAFFIC;
    *pHeader++ = MSBOF(TLS1_2_PROTOCOL_VERSION);
    *pHeader++ = LSBOF(TLS1_2_PROTOCOL_VERSION);
    *pHeader++ = MSBOF(CiphertextLength);
    *pHeader++ = LSBOF(CiphertextLength);


    AuthInfo.pbAuthData = pbOutput;
    AuthInfo.cbAuthData = HeaderSize;
    AuthInfo.pbTag = pbOutput + HeaderSize + cbInput;
    AuthInfo.cbTag = SSL_AES_GMC_AUTH_TAG_LENGTH;

    // The per-record nonce for the AEAD construction is formed as follows:
    // 1.  The 64 - bit record sequence number is encoded in network byte
    //     order and padded to the left with zeros to iv_length.
    // 2.  The padded sequence number is XORed with the static
    //     client_write_iv or server_write_iv, depending on the role.
    CopyMemory(pNonce, pbIV, cbIV);
    rgbNonce[1] ^= htonll(SequenceNumber);

    Status = BCryptEncrypt(
        Key,
        pbInput,
        cbInput,
        &AuthInfo,
        NULL,               // pbIV
        0,                  // cbIV
        pbOutput + HeaderSize,
        cbInput,
        &cbResult,
        0);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    if (cbResult != cbInput)
    {
        return (DWORD)NTE_FAIL;
    }

    // Set the output values.
    *pcbResult = RecordSize;
    return Status;
}

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

HRESULT
QueryAndDeserializeRemoteCertContext(
    _In_ PVOID phContext,
    _In_ BOOLEAN fQueryOutProc,
    _Out_ PCCERT_CONTEXT* ppCertContext)
{
    HRESULT status = NOERROR;
    CERT_BLOB SerializedRemoteCert = { 0 };
    ULONG ulAttribute = fQueryOutProc ?
        SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT :
        SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT_INPROC;

    if (phContext == NULL ||
        ppCertContext == NULL)
    {
        return NTE_INVALID_PARAMETER;
    }
    printf("- QueryContextAttributes - SECPKG_ATTR_SERIALIZED_REMOTE_CERT_CONTEXT%s", fQueryOutProc ? "" : "_INPROC");

    status = QueryContextAttributes(
            reinterpret_cast<PCtxtHandle>(phContext),
            ulAttribute,
            &SerializedRemoteCert);

    if (FAILED(status))
    {
        if (status != SEC_E_NO_CREDENTIALS)
        {
            printf("- Error 0x%x returned by %sQueryContextAttributes\n",
                status,
                "");
        }
        return status;
    }
    if (SerializedRemoteCert.pbData != NULL)
    {
        //pfnFreeContextBuffer(SerializedRemoteCert.pbData);
    }

    return status;
}

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