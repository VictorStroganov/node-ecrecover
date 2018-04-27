#include "common.h"

void HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    if(!err) err = 1;
    exit(err);
}

unsigned char* GetPurePubKey(const char *container, const char *pin)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE *pbKeyBlob = NULL;
    DWORD dwBlobLen;

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

    // Retrieving signature public key from key storage
    if(!CryptGetUserKey(
            hProv,
            AT_KEYEXCHANGE,
            &hKey))
    {
        HandleError("Error during CryptGetUserKey for signkey.");
    }

    // Determining public key BLOB length
    if(!CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            NULL,
            &dwBlobLen))
    {
        HandleError("Error computing BLOB length.");
    }

    // Memory allocation for public key BLOB
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    if(!pbKeyBlob)
        HandleError("Out of memory. \n");

    // Export public key to BLOB
    if(!CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob,
            &dwBlobLen))
    {
        HandleError("Error during CryptExportKey.");
    }

    // Releasing key
    if(hKey)
        CryptDestroyKey(hKey);

    // Releasing of provider descriptor
    if(hProv)
        CryptReleaseContext(hProv, 0);

    // returning pointer on pure last 64 bytes of BLOB
    return pbKeyBlob + 37;
}

char* ConvertPubkeyBytesToString(unsigned const char *pubKey)
{
    static char result[129];
    CHAR rgbDigits[] = "0123456789abcdef";
    DWORD i;

    for (i = 0; i < 64; i++) {
        result[i*2] = rgbDigits[pubKey[i] >> 4];
        result[i*2+1] = rgbDigits[pubKey[i] & 0xf];
    }
    result[128] = '\0';
    return result;
}
/*
HCRYPTPROV InitializeProvider(const char *container, const char *pin)
{
    HCRYPTPROV hCryptProv;
    LPCSTR pbContainer = (LPCSTR)container;
    BYTE *pbContainerPass = (BYTE *)pin;

    // Initializing crypto provider
    if(!CryptAcquireContext(
            &hCryptProv,
            pbContainer,
            NULL,
            PROV_GOST_2012_256,
            CRYPT_SILENT))
    {
        HandleError("Acquiring provider context failed.");
    }

    // Setting pin code for key storage
    if(!CryptSetProvParam(
            hCryptProv,
            PP_KEYEXCHANGE_PIN,
            pbContainerPass,
            0))
    {
        HandleError("Setting container pin failed.");
    }

    return hCryptProv;
}

unsigned char* GetPurePubKey(const char *container, const char *pin)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE *pbKeyBlob = NULL;
    DWORD dwBlobLen;

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

    // Retrieving signature public key from key storage
    if(!CryptGetUserKey(
            hProv,
            AT_KEYEXCHANGE,
            &hKey))
    {
        HandleError("Error during CryptGetUserKey for signkey.");
    }

    // Determining public key BLOB length
    if(!CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            NULL,
            &dwBlobLen))
    {
        HandleError("Error computing BLOB length.");
    }

    // Memory allocation for public key BLOB
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    if(!pbKeyBlob)
        HandleError("Out of memory. \n");

    // Export public key to BLOB
    if(!CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob,
            &dwBlobLen))
    {
        HandleError("Error during CryptExportKey.");
    }

    // Releasing key
    if(hKey)
        CryptDestroyKey(hKey);

    // Releasing of provider descriptor
    if(hProv)
        CryptReleaseContext(hProv, 0);

    // returning pointer on pure last 64 bytes of BLOB
    return pbKeyBlob + 37;
}

char* ConvertPubkeyBytesToString(unsigned const char *pubKey)
{
    static char result[129];
    CHAR rgbDigits[] = "0123456789abcdef";
    DWORD i;

    for (i = 0; i < 64; i++) {
        result[i*2] = rgbDigits[pubKey[i] >> 4];
        result[i*2+1] = rgbDigits[pubKey[i] & 0xf];
    }
    result[128] = '\0';
    return result;
}
*/
uint8_t* datahex(const char* string)
{
    if(string == NULL)
    {
        return NULL;
    }

    size_t slength = strlen(string);

    if(slength % 2 != 0) // must be even
    {
        return NULL;
    }
    size_t dlength = slength / 2;

    uint8_t* data = malloc(dlength);
    memset(data, 0, dlength);

    size_t index = 0;

    while (index < slength)
    {
        char c = string[index];

        int value = 0;
        if(c >= '0' && c <= '9')
        {
            value = (c - '0');
        }
        else if (c >= 'A' && c <= 'F')
        {
            value = (10 + (c - 'A'));
        }
        else if (c >= 'a' && c <= 'f')
        {
            value = (10 + (c - 'a'));
        }
        else
        {
            return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}