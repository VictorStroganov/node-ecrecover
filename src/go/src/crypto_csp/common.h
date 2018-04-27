#ifndef COMMON_H
#define COMMON_H

#define UNIX
#define SIZEOF_VOID_P 8
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CRYPTOPRO_DEF_PROV          "Crypto-Pro GOST R 34.10-2012 KC1 CSP" //TODO: switch to dynamic getting

#include <stdio.h>
#include <stdlib.h>
#include <printf.h>
#include <memory.h>
#include <stdint.h>
#include </opt/cprocsp/include/cpcsp/WinCryptEx.h>
#include </opt/cprocsp/include/cpcsp/CSP_WinDef.h>
#include </opt/cprocsp/include/cpcsp/CSP_WinCrypt.h>

void HandleError(const char*);
//HCRYPTPROV InitializeProvider(const char*, const char*);
unsigned char* GetPurePubKey(const char*, const char*);
//char* ConvertPubkeyBytesToString(unsigned const char*);
uint8_t* datahex(const char*);

#endif