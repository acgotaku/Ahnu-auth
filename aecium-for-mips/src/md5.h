#pragma once
#include <string.h>

typedef unsigned int word32;

struct MD5Context {
	word32 buf[4];
	word32 bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, unsigned len);
void MD5Final(struct MD5Context *context, unsigned char *digest);
void MD5Transform(word32 buf[4], word32 const in[16]);
void MD5Calc(unsigned char *dest, unsigned char *src, int srclen);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
// typedef struct MD5Context MD5_CTX;
