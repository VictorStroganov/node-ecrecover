#include "common.h"
//#include "container.h"
//#include "certificate.h"
#include "csp.h"
//#include "tls.h"

static const char *blobHeader = "06200000492e00004d41473100020000301306072a85030202230106082a85030701010202";

unsigned char* CalculateHash(const char *msg, const uint32_t len)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE *pbHash;
    BYTE *pbBuffer= (BYTE *)msg;
    DWORD dwBufferLen = (DWORD)len;
    DWORD cbHash;

    if(!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_GOST_2012_256,
            CRYPT_VERIFYCONTEXT))
    {
        HandleError("Error during CryptAcquireContext.");
    }

    if(!CryptCreateHash(
            hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
    {
        HandleError("Error during CryptCreateHash.");
    }

    cbHash = GR3411LEN;
    pbHash = (BYTE*)malloc(cbHash);
    if(!pbHash)
        HandleError("Out of memory.\n");

    //--------------------------------------------------------------------
    // Вычисление криптографического хеша буфера.
    if(!CryptHashData(
            hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        HandleError("Error during CryptHashData.");
    }

    if(!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &cbHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        HandleError("CryptGetHashParam failed");
    }

    if(hHash)
        CryptDestroyHash(hHash);

    if(hProv)
        CryptReleaseContext(hProv, 0);

    return pbHash;
}

unsigned char* SignHash(const char *container, const char *pin, const uint8_t *msg)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE *pbSignature = NULL;
    DWORD dwSigLen;

    BYTE *pbHash= (BYTE *)msg;
    LPCSTR pbContainer= (LPCSTR)container;
    BYTE *pbContainerPass= (BYTE *)pin;

    // Initializing crypto provider
    if(!CryptAcquireContext(
            &hProv,
            pbContainer,
            NULL,
            PROV_GOST_2012_256,
            0))
    {
        HandleError("Error during CryptAcquireContext.");
    }

    // Setting pin code for key storage
    if(!CryptSetProvParam(
            hProv,
            PP_KEYEXCHANGE_PIN,
            pbContainerPass,
            0))
    {
        HandleError("Error during CryptSetProvParam.");
    }

    // Creating hash object
    if(!CryptCreateHash(
            hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
    {
        HandleError("Error during CryptCreateHash.");
    }

    // Setting hash value
    if(!CryptSetHashParam(
            hHash,
            HP_HASHVAL,
            pbHash,
            0))
    {
        HandleError("Error during CryptSetHashParam.");
    }

    // Determining signature length
    dwSigLen = 0;
    if(!CryptSignHash(
            hHash,
            AT_KEYEXCHANGE,
            NULL,
            0,
            NULL,
            &dwSigLen))
    {
        HandleError("Error during determining size of signature in CryptSignHash.");
    }

    // Memory allocation for signature
    pbSignature = (BYTE *)malloc(dwSigLen);
    if(!pbSignature)
        HandleError("Out of memory.");

    // Hash signing
    if(!CryptSignHash(
            hHash,
            AT_KEYEXCHANGE,
            NULL,
            0,
            pbSignature,
            &dwSigLen))
    {
        HandleError("Error during CryptSignHash.");
    }

    // Destroying hash object
    if(hHash)
        CryptDestroyHash(hHash);

    // Releasing of provider descriptor
    if(hProv)
        CryptReleaseContext(hProv, 0);

    return pbSignature;
}

uint8_t SignatureVerify(const char *container, const char *pin, const uint8_t *msg, uint8_t *signature, uint8_t *pubkey)
{
    uint8_t result = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE *pbHash= (BYTE *)msg;
    LPCSTR pbContainer= (LPCSTR)container;
    BYTE *pbContainerPass= (BYTE *)pin;
    BYTE *pbSignature = signature;
    DWORD dwSigLen = 64;
    HCRYPTKEY hPubKey = 0;
    DWORD dwBlobLen = 101;
    BYTE *pbKeyBlob = malloc(dwBlobLen);
    uint8_t *bHeader = datahex(blobHeader);
    memcpy(pbKeyBlob, bHeader, 37);
    memcpy(pbKeyBlob + 37, pubkey, 64);

    // Initializing crypto provider
    if(!CryptAcquireContext(
            &hProv,
            pbContainer,
            NULL,
            PROV_GOST_2012_256,
            0))
    {
        HandleError("Error during CryptAcquireContext.");
    }

    // Setting pin code for key storage
    if(!CryptSetProvParam(
            hProv,
            PP_KEYEXCHANGE_PIN,
            pbContainerPass,
            0))
    {
        HandleError("Error during CryptSetProvParam.");
    }

    if(!CryptImportKey(
            hProv,
            pbKeyBlob,
            dwBlobLen,
            0,
            0,
            &hPubKey))
    {
        HandleError("Public key import failed.");
    }

    // Creating hash object
    if(!CryptCreateHash(
            hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
    {
        HandleError("Error during CryptCreateHash.");
    }

    // Setting hash value
    if(!CryptSetHashParam(
            hHash,
            HP_HASHVAL,
            pbHash,
            0))
    {
        HandleError("Error during CryptSetHashParam.");
    }

    if(CryptVerifySignature(
            hHash,
            pbSignature,
            dwSigLen,
            hPubKey,
            NULL,
            0))
    {
        result = 1;
    }

    free(bHeader);
    free(pbKeyBlob);

    // Destroying hash object
    if(hHash)
        CryptDestroyHash(hHash);

    // Releasing of provider descriptor
    if(hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}