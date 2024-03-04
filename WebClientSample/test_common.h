#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

extern BOOL g_fAllocateMemory;

#define LSBOF(x)    ((UCHAR) ((x) & 0xFF))
#define MSBOF(x)    ((UCHAR) (((x) >> 8) & 0xFF))
#define COMBINETWOBYTES(Msb, Lsb)  ((DWORD) (((DWORD) (Msb) << 8) | (DWORD) (Lsb)))

#define TLS_RECORD_HEADER sizeof(BYTE) + sizeof(WORD) + sizeof(WORD)
#define HANDSHAKE_TRAFFIC 0x16
#define APPLICATION_TRAFFIC 0x17

#define htonll(x)            \
            ( ( ((x) >> 56) & 0x00000000000000FFLL ) |       \
              ( ((x) >> 40) & 0x000000000000FF00LL ) |       \
              ( ((x) >> 24) & 0x0000000000FF0000LL ) |       \
              ( ((x) >>  8) & 0x00000000FF000000LL ) |       \
              ( ((x) <<  8) & 0x000000FF00000000LL ) |       \
              ( ((x) << 24) & 0x0000FF0000000000LL ) |       \
              ( ((x) << 40) & 0x00FF000000000000LL ) |       \
              ( ((x) << 56) & 0xFF00000000000000LL ) )

#define MAX_TLS_RECORD_PLAINTEXT_SIZE   0x4000
#define SSL_MAX_AEAD_NONCE_IMPLICIT_LENGTH  4
#define SSL_AES_GMC_NONCE_IMPLICIT_LENGTH   4
#define SSL_AES_GMC_NONCE_EXPLICIT_LENGTH   8
#define SSL_AES_GMC_NONCE_LENGTH   \
    (SSL_AES_GMC_NONCE_IMPLICIT_LENGTH + SSL_AES_GMC_NONCE_EXPLICIT_LENGTH)

#define SSL_AES_GMC_AUTH_TAG_LENGTH         16

#define TLS_HASH_SHA256_DIGEST_LEN      32
#define TLS_HASH_SHA384_DIGEST_LEN      48

#define MAX_AES_KEY_SIZE_IN_BYTES 32

#define HeaderAndTagSize TLS_RECORD_HEADER + SSL_AES_GMC_AUTH_TAG_LENGTH
#define MAX_TLS_RECORD_CIPHERTEXT_SIZE HeaderAndTagSize + MAX_TLS_RECORD_PLAINTEXT_SIZE

#define SERVER_SPEAKS_FIRST_MESSAGE_PREFIX "SSFM:"
#define SERVER_SPEAKS_FIRST_MESSAGE_PREFIX_SIZE sizeof(SERVER_SPEAKS_FIRST_MESSAGE_PREFIX) - 1

#define TLS_EXTENSION_CH_DUPLICATE_SUPPORTED_VERSIONS  1
#define TLS_EXTENSION_CH_DUPLICATE_UNKNOWN 2
#define TLS_EXTENSION_CH_MISORDERED_PSK 3
#define TLS_EXTENSION_SH_DUPLICATE  4
#define TLS_EXTENSION_HRR_DUPLICATE 5
#define TLS_EXTENSION_CH_EMPTY_PSK_BINDERS 6
#define TLS_EXTENSION_CH_EMPTY_PSK_IDENTITIES 7

    typedef struct _QUIC_KEYS {
        BCRYPT_KEY_HANDLE hClientTrafficSecret;
        BCRYPT_KEY_HANDLE hClientWriteKey;
        BYTE rgClientIV[MAX_AES_KEY_SIZE_IN_BYTES];
        BYTE cbClientIV;
        ULONGLONG ClientSequenceNumber;
        BCRYPT_KEY_HANDLE hServerTrafficSecret;
        BCRYPT_KEY_HANDLE hServerWriteKey;
        BYTE rgServerIV[MAX_AES_KEY_SIZE_IN_BYTES];
        BYTE cbServerIV;
        ULONGLONG ServerSequenceNumber;
    } QUIC_KEYS, * PQUIC_KEYS;


    extern SECURITY_STATUS(*pfnFreeContextBuffer)(PVOID);

    DWORD
        GetPSKSize(
            __in const PSEC_PRESHAREDKEY pPSK);

    DWORD
        GetPSKIdentitySize(
            __in const PSEC_PRESHAREDKEY_IDENTITY pPSKIdentity);

    DWORD ReadHexString(
        __in const PCHAR pszHexString,
        __in WORD cbBufferSize,
        __out PBYTE pBuffer,
        __out PWORD pcbWritten);

#define MAX_INFO_BUFFER 256
#define COUNT_OF_TRAFFIC_SECRETS 4
#define TRAFFIC_SECRET_MAX_SIZE 0x200

    void
        PrintSchannelProtocol(
            _In_                                DWORD   dwProtocol,
            _Inout_updates_z_(MAX_INFO_BUFFER)  char* szString);

    DWORD
        InplaceStringSplit(
            _In_ CHAR chDelimiter,
            _In_ PSTR pszTargetString,
            _Inout_ PDWORD pdwEntriesCount,
            _Out_writes_to_(*pdwEntriesCount, *pdwEntriesCount) PZPSTR ppszEntries);

    DWORD
        AllocateOutputBuffer(
            _In_ PSecBuffer pOutBuffer,
            _In_ BOOLEAN fUserAllocate,
            _In_ BOOLEAN fAllocateSmall,
            _In_opt_ DWORD dwSize);

    VOID
        FreeOutputBuffer(
            _In_ PSecBuffer pOutBuffer);

    DWORD
        TlsExpandLabel(
            _In_ BCRYPT_KEY_HANDLE hPrk,
            _In_opt_ LPCSTR pLabel,
            _In_reads_opt_(cbHash) PBYTE pbHash,
            _In_ BYTE cbHash,
            _Out_writes_(cbOkm) PBYTE pbOkm,
            _In_ WORD cbOkm);

    DWORD
        CreateTrafficSecretKey(
            _Inout_ BCRYPT_KEY_HANDLE* pKey,
            _In_ PWSTR pwszHash,
            _In_reads_bytes_(cbRawSecret) PBYTE pbRawSecret,
            _In_ DWORD cbRawSecret);

    DWORD
        CreateQuicKeys(
            _Inout_ PQUIC_KEYS pQuicKeys,
            _Inout_ BCRYPT_ALG_HANDLE* hSymmetricAlg,
            _In_ PSEC_TRAFFIC_SECRETS pTrafficSecret);

    VOID
        DestroyQuicKeys(
            _In_ PQUIC_KEYS pQuicKeys);

    DWORD
        QuicEncrypt(
            _In_ PQUIC_KEYS pQuicKey,
            _In_ BOOLEAN fServer,
            _Inout_ PSecBuffer pData);

    DWORD
        QuicDecrypt(
            _In_ PQUIC_KEYS pQuicKey,
            _In_ BOOLEAN fServer,
            _Inout_ PSecBuffer pData);

    DWORD
        CustomRecordLayer(
            _Inout_ BCRYPT_ALG_HANDLE* hSymmetricAlg,
            _In_ PSecBuffer pInBuffers,
            _In_ PSecBuffer pOutBuffers,
            _In_ DWORD dwOutputBuffersCount,
            _In_ BOOLEAN fServer,
            _In_ DWORD dwStatus,
            _Inout_ PQUIC_KEYS pHandshakeQuicKeys,
            _Inout_ PQUIC_KEYS pApplicationQuicKeys,
            _Inout_ PBYTE pTokenBuffer,
            _Inout_ PDWORD pcbIoBuffer);

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
            _In_ ULONGLONG SequenceNumber);

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
            _In_ ULONGLONG SequenceNumber);

    DWORD
        PackBufferIntoRecords(
            _In_opt_ PQUIC_KEYS pQuicKeys,
            _In_ PBYTE pbInput,
            _In_ DWORD cbInput,
            _In_ DWORD dwMessageStart,
            _In_ DWORD dwMessageEnd,
            _In_ DWORD dwContentType,
            _In_ BOOLEAN fServer,
            _Inout_ PBYTE pbOutput,
            _In_ DWORD cbOutput,
            _Out_ PDWORD pcbResult);

    DWORD
        RemoveRecordLayerAndOrEncryption(
            _In_ PQUIC_KEYS pQuicHandshakeKeys,
            _In_ BOOLEAN fServer,
            _Inout_ PBYTE pbInput,
            _Inout_ PDWORD pcbInput);


    HRESULT
        QueryAndDeserializeRemoteCertContext(
            _In_ PVOID phContext,
            _In_ BOOLEAN fOutProc,
            _Out_ PCCERT_CONTEXT* ppCertContext);

    const PVOID*
        CheckDelayLoadSchannelExportedFunctions();

    PCCERT_CONTEXT
        FindFirstCertContextWithKey(_In_ HCERTSTORE hStore);

    DWORD
        ReadPfxStore(
            _In_ LPSTR pszPfxPath,
            _Out_ HCERTSTORE* phPfxCertStore);

#ifdef __cplusplus
}
#endif

#endif // __TEST_COMMON_H__

