#ifndef JS_PKI_XML_H
#define JS_PKI_XML_H

#include <stdint.h>
#include "js_bin.h"

#ifdef __cplusplus
extern "C" {
#endif

void JS_XML_init();
void JS_XML_final();

int JS_XML_signWithInfo( const char *pSrcFile, const char* pPriKeyPath, const char *pDstFile );
int JS_XML_signDoc( const char *pSrcFile, const char* pPriKeyPath, const char *pDstFile );
int JS_XML_verify( const char* pSrcFile, const char* pPubKeyPath );

int JS_XML_encryptWithInfo(const char* pSrcFile, const BIN *pKey, const BIN *pData, const char *pDstFile );
int JS_XML_encrypt( const char* pSrcFile, const BIN *pKey, const char *pDstFile );
int JS_XML_decrypt(const char* pSrcFile, const BIN *pKey, const char *pDstFile );

#ifdef __cplusplus
};
#endif

#endif // JS_PKI_XML_H
