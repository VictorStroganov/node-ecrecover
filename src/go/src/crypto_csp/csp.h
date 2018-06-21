#ifndef CSP_H
#define CSP_H

#define GR3411LEN  32

static unsigned char* CalculateHash(const char *msg, const uint32_t len);
static unsigned char* SignHash(const char *container, const char *pin, const uint8_t *msg);
static uint8_t SignatureVerify(const uint8_t*, uint8_t*, uint8_t*);

#endif