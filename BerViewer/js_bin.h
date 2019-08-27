#ifndef __JS_BIN_H__
#define __JS_BIN_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define			JS_PEM_TYPE_RSA_PRIVATE_KEY			1
#define			JS_PEM_TYPE_RSA_PUBLIC_KEY			2
#define			JS_PEM_TYPE_CSR						3
#define			JS_PEM_TYPE_CERTIFICATE				4
#define			JS_PEM_TYPE_CRL						5
#define			JS_PEM_TYPE_PRIVATE_KEY				6
#define			JS_PEM_TYPE_PUBLIC_KEY				7
#define			JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY	8

typedef struct _BIN {
	int				nLen;
	unsigned char	*pVal;
} BIN;


typedef struct _BINList {
	BIN					Bin;
	struct _BINList		*pNext;
} BINList;

void* JS_malloc(size_t size);
void* JS_calloc(size_t nelem, size_t elsize);
void* JS_realloc(void *ptr, size_t size);
void JS_free(void *ptr);

int JS_BIN_set(BIN *pBin, const unsigned char *pValue, int nLength);
void JS_BIN_reset( BIN *pBin );
int JS_BIN_append(BIN *pBIN, const unsigned char *pAppendVal, int nAppendLen);
int JS_BIN_appendBin( BIN *pBin, const BIN *pAppend );
int JS_BIN_copy( BIN *pDst, const BIN *pSrc );
int JS_BIN_cmp( const BIN *pSrc, const BIN *pDst );
int JS_BIN_fileWrite( const BIN *pBin, const char *pFilePath );
int JS_BIN_fileRead( const char *pFilePath, BIN *pBin );
int JS_BIN_encodeHex( const BIN *pBin, char **ppHex );
int JS_BIN_decodeHex( const char *pHex, BIN *pBin );
int JS_BIN_encodeBase64( const BIN *pBin, char **ppBase64 );
int JS_BIN_decodeBase64( const char *pBase64, BIN *pBin );
int JS_BIN_encodePEM( int nType, const BIN *pBin, char **ppPEM );
int JS_BIN_decodePEM( const char *pPEM, int *pType, BIN *pBin );
int JS_BIN_encodeBase64URL( const BIN *pBin, char **ppBase64URL );
int JS_BIN_decodeBase64URL( const char *pBase64URL, BIN *pBin );

#endif