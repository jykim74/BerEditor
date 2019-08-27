#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "js_bin.h"

void * JS_malloc(size_t size)
{
	return malloc(size);
}

void * JS_calloc(size_t nelem, size_t elsize)
{
	return calloc(nelem, elsize);
}

void * JS_realloc(void * ptr, size_t size)
{
	return realloc(ptr, size);
}

void JS_free(void * ptr)
{
	free(ptr);
}

int JS_BIN_set(BIN * pBin, const unsigned char * pValue, int nLength)
{
	int			nRet = 0;

	if (pBin == NULL || pValue == NULL || nLength < 0)
		return -1;

	if (nLength == 0)
	{
		memset(pBin, 0x00, sizeof(BIN));
		nRet = 0;
		goto end;
	}

	pBin->pVal = (unsigned char *)JS_malloc(nLength);
	if (pBin->pVal == NULL)
	{
		nRet = -1;
		goto end;
	}

	pBin->nLen = nLength;
	memcpy(pBin->pVal, pValue, nLength);
	nRet = 0;

end :

	return nRet;
}

void JS_BIN_reset( BIN *pBin )
{
	if( pBin == NULL ) return;

	if( pBin->pVal != NULL )
	{
		JS_free( pBin->pVal );
		pBin->pVal = NULL;
		pBin->nLen = 0;
	}

	pBin->nLen = 0;
}

int JS_BIN_append(BIN * pBIN, const unsigned char * pAppendVal, int nAppendLen)
{
	if (nAppendLen < 0) return -1;

	pBIN->pVal = (unsigned char *)JS_realloc(pBIN->pVal, pBIN->nLen + nAppendLen);

	memcpy(pBIN->pVal + pBIN->nLen, pAppendVal, nAppendLen);
	pBIN->nLen += nAppendLen;

	return 0;
}

int JS_BIN_appendBin( BIN *pBin, const BIN *pAppend )
{
	if( pBin == NULL || pAppend == NULL ) return -1;

	return JS_BIN_append( pBin, pAppend->pVal, pAppend->nLen );
}

int JS_BIN_copy( BIN *pDst, const BIN *pSrc )
{
	if( pDst == NULL || pSrc == NULL || pSrc->nLen <= 0 ) return -1;

	JS_BIN_reset( pDst );

	pDst->nLen = pSrc->nLen;
	pDst->pVal = (unsigned char *)JS_malloc( pDst->nLen );
	memcpy( pDst->pVal, pSrc->pVal, pDst->nLen );

	return 0;
}

int JS_BIN_cmp( const BIN *pSrc, const BIN *pDst )
{
	int		nRet = 0;

	if( pSrc == NULL || pDst == NULL ) return -1;

	if( pSrc->nLen != pDst->nLen ) return -1;

	nRet = memcpy( pSrc->pVal, pDst->pVal, pSrc->nLen );

	return nRet;
}

int JS_BIN_fileWrite( const BIN *pBin, const char *pFilePath )
{
	int			nRet = -1;
	FILE		*pFP = NULL;

	if( pBin == NULL || pFilePath == NULL ) return -1;

	pFP = fopen( pFilePath, "wb" );
	if( pFP == NULL )
	{
		fprintf( stderr, "file open fail(%s:%d)\n", pFilePath, errno );
		return -2;
	}

	nRet = fwrite( pBin->pVal, 1, pBin->nLen, pFP );
	if( nRet != pBin->nLen )
	{
		fprintf( stderr, "file write fail\n" );
		fclose( pFP );
		return -3;
	}

	fclose( pFP );
	return 0;
}

int JS_BIN_fileRead( const char *pFilePath, BIN *pBin )
{
	int				nRet = -1;
	FILE			*pFP = NULL;
	int				nLen = 0;

	if( pFilePath == NULL || pBin == NULL ) return -1;

	pFP = fopen( pFilePath, "rb" );
	if( pFP == NULL )
	{
		fprintf( stderr, "file open fail(%s:%d)\n", pFilePath, errno );
		return -2;
	}

	fseek( pFP, 0, SEEK_END );
	nLen = ftell( pFP );

	if( nLen == -1 )
	{
		fprintf( stderr, "ftell error(%s:%d)\n", strerror(errno), errno );
		fclose( pFP );
		return -3;
	}

	fseek( pFP, 0, SEEK_SET );
	pBin->pVal = (unsigned char *)JS_calloc( 1, nLen + 1 );
	if( pBin->pVal == NULL )
	{
		fprintf( stderr, "out of memory\n" );
		fclose( pFP );
		return -4;
	}

	nRet = fread( pBin->pVal, 1, nLen, pFP );
	if( nRet != nLen )
	{
		fprintf( stderr, "file read fail\n" );
		fclose( pFP );
		JS_free( pBin->pVal );
		return -5;
	}

	fclose( pFP );
	pBin->nLen = nLen;

	return 0;
}

int JS_BIN_encodeHex( const BIN *pBin, char **ppHex )
{
	int			i;

	if( (pBin == NULL ) || (pBin->nLen <= 0 ) ) return -1;

	*ppHex = (char *)JS_calloc( 1, pBin->nLen * 2 + 3 );
	if( *ppHex == NULL ) return -1;

	for( i = 0; i < pBin->nLen; i++ )
		sprintf(((*ppHex) + (i*2)), "%02X", (pBin->pVal[i]) & 0xFF );

	(*ppHex)[(pBin->nLen*2)] = 0x00;

	return 0;
}

int JS_BIN_decodeHex( const char *pHex, BIN *pBin )
{
	int			i;
	unsigned int	tmp;

	if( pHex == NULL || pBin == NULL ) return -1;

	pBin->nLen = strlen( pHex ) / 2;
	pBin->pVal = JS_calloc( pBin->nLen, 1 );

	for( i = 0; i < pBin->nLen; i++ )
	{
		sscanf(((char *)pHex + (i*2)), "%02X", &tmp);
		pBin->pVal[i] = tmp & 0xFF;
	}

	return 0;
}

int JS_BIN_encodeBase64( const BIN *pBin, char **ppBase64 )
{
	unsigned char *pOutput = NULL;
	int i, j = 0;
	unsigned char buf[4] = "";
	static const char vec[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if ( pBin == NULL || pBin->nLen <= 0) return -1;

	pOutput = (unsigned char *)M_calloc(1, pBin->nLen * 2 + 4);

	for (i = 0; i < pBin->nLen; i++) {
		if (((i / 3) > 0) && ((i % 3) == 0)) {
			*(pOutput + j + 0) = vec[(buf[0] & 0xFC) >> 2];
			*(pOutput + j + 1) = vec[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
			*(pOutput + j + 2) = vec[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
			*(pOutput + j + 3) = vec[buf[2] & 0x3F];
			j += 4;
		}
		buf[i % 3] = 0; buf[i % 3] = *(pBin->pVal + i);
	}

	switch (i % 3) {
	case 1:
		buf[1] = 0x0;
		*(pOutput + j + 0) = vec[(buf[0] & 0xFC) >> 2];
		*(pOutput + j + 1) = vec[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
		*(pOutput + j + 2) = '=';
		*(pOutput + j + 3) = '=';
		*(pOutput + j + 4) = '\0';
		break;
	case 2:
		buf[2] = 0x0;
		*(pOutput + j + 0) = vec[(buf[0] & 0xFC) >> 2];
		*(pOutput + j + 1) = vec[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
		*(pOutput + j + 2) = vec[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
		*(pOutput + j + 3) = '=';
		*(pOutput + j + 4) = '\0';
		break;
	case 0:
		*(pOutput + j + 0) = vec[(buf[0] & 0xFC) >> 2];
		*(pOutput + j + 1) = vec[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
		*(pOutput + j + 2) = vec[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
		*(pOutput + j + 3) = vec[buf[2] & 0x3F];
		*(pOutput + j + 4) = '\0';
		break;
	}

	*ppBase64 = (char *)pOutput;
	return 0;
}

int JS_BIN_decodeBase64( const char *pBase64, BIN *pBin )
{
	int i, j = 0;
	unsigned char buf[5] = "";
	unsigned char *pSrc = NULL;
	int nIn = 0;

	if (pBase64 == NULL || pBin == NULL) return -1;

	nIn = strlen(pBase64);

	if (nIn <= 0) return -1;

	pBin->pVal = (unsigned char *)M_calloc(1, nIn + 1);
	pSrc = (unsigned char *)M_calloc(1, nIn + 1);

	memcpy(pSrc, pBase64, nIn);

	for (i = 0; i < nIn; i++) {
		if (((i / 4) > 0) && ((i % 4) == 0)) {
			pBin->pVal[j + 0] = (buf[0] << 2) | (buf[1] >> 4);
			pBin->pVal[j + 1] = (buf[1] << 4) | (buf[2] >> 2);
			pBin->pVal[j + 2] = (buf[2] << 6) | buf[3];
			j += 3;
		}
		if ((*(pSrc + i) >= 'A') && (*(pSrc + i) <= 'Z'))
			buf[i % 4] = *(pSrc + i) - 'A';
		else if ((*(pSrc + i) >= 'a') && (*(pSrc + i) <= 'z'))
			buf[i % 4] = *(pSrc + i) - 'a' + 26;
		else if ((*(pSrc + i) >= '0') && (*(pSrc + i) <= '9'))
			buf[i % 4] = *(pSrc + i) - '0' + 52;
		else if (*(pSrc + i) == '+')
			buf[i % 4] = 62;
		else if (*(pSrc + i) == '/')
			buf[i % 4] = 63;
		else if (*(pSrc + i) == '=') {
			buf[i % 4] = 0;
			break;
		}
	}

	if (pSrc) JS_free(pSrc);

	switch (i % 4) {
	case 3:
		pBin->pVal[j + 2] = '\0';
		pBin->pVal[j + 0] = (buf[0] << 2) | (buf[1] >> 4);
		pBin->pVal[j + 1] = (buf[1] << 4) | (buf[2] >> 2);
		pBin->nLen = j + 2;
		break;
	case 2:
		pBin->pVal[j + 1] = '\0';
		pBin->pVal[j + 0] = (buf[0] << 2) | (buf[1] >> 4);
		pBin->nLen = j + 1;
		break;
	case 1:
		pBin->pVal[j + 1] = '\0';
		pBin->nLen = j;
		break;
	case 0:
		pBin->pVal[j + 0] = (buf[0] << 2) | (buf[1] >> 4);
		pBin->pVal[j + 1] = (buf[1] << 4) | (buf[2] >> 2);
		pBin->pVal[j + 2] = (buf[2] << 6) | buf[3];
		pBin->pVal[j + 3] = '\0';
		pBin->nLen = j + 3;
	}

	return 0;
}

static int _getHeaderLine(const char *pSrc, char *pLine)
{
	int	nMaxPos = 1024;
	int i = 0;

	if (pSrc[0] != '-') return -1;

	for (i = 0; i < nMaxPos; i++)
	{
		if (pSrc[i] == '\r')
		{
			if (pSrc[i + 1] == '\n') i++;
			break;
		}
		else if (pSrc[i] == '\n')
		{
			if (pSrc[i + 1] == '\r') i++;

			break;
		}

		pLine[i] = pSrc[i];
	}

	return i;
}

int JS_BIN_encodePEM( int nType, const BIN *pBin, char **ppPEM )
{
	int				nRet = 0;
	char			sHeader[128];
	char			sTail[128];
	const char		*pDelim = "\r\n";
	char			*pPEM = NULL;
	char			*pBase64 = NULL;

	int				nDelimLen = 0;
	int				nDelimCount = 0;
	int				nBase64Len = 0;
	int				nHeaderLen = 0;
	int				nTailLen = 0;
	int				nPos = 0;
	int				nBase64Pos = 0;
	int				nSize = 0;

	memset(sHeader, 0x00, sizeof(sHeader));
	memset(sTail, 0x00, sizeof(sTail));

	if (nType == JS_PEM_TYPE_RSA_PRIVATE_KEY)
	{
		sprintf(sHeader, "-----BEGIN RSA PRIVATE KEY-----");
		sprintf(sTail, "-----END RSA PRIVATE KEY-----");
	}
	else if (nType == JS_PEM_TYPE_RSA_PUBLIC_KEY)
	{
		sprintf(sHeader, "-----BEGIN RSA PUBLIC KEY-----");
		sprintf(sTail, "-----END RSA PRIVATE KEY-----");
	}
	else if (nType == JS_PEM_TYPE_CSR)
	{
		sprintf(sHeader, "-----BEGIN CERTIFICATE REQUEST-----");
		sprintf(sTail, "-----END CERTIFICATE REQUEST-----");
	}
	else if (nType == JS_PEM_TYPE_CERTIFICATE)
	{
		sprintf(sHeader, "-----BEGIN CERTIFICATE-----");
		sprintf(sTail, "-----END CERTIFICATE-----");
	}
	else if (nType == JS_PEM_TYPE_CRL)
	{
		sprintf(sHeader, "-----BEGIN X509 CRL-----");
		sprintf(sTail, "-----END X509 CRL-----");
	}
	else if (nType == JS_PEM_TYPE_PRIVATE_KEY)
	{
		sprintf(sHeader, "-----BEGIN PRIVATE KEY-----");
		sprintf(sTail, "-----END PRIVATE KEY-----");
	}
	else if (nType == JS_PEM_TYPE_PUBLIC_KEY)
	{
		sprintf(sHeader, "-----BEGIN PUBLIC KEY-----");
		sprintf(sTail, "-----END PUBLIC KEY-----");
	}
	else if (nType == JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY)
	{
		sprintf(sHeader, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
		sprintf(sTail, "-----END ENCRYPTED PRIVATE KEY-----");
	}
	else
	{
		fprintf(stderr, "Invalid PEM type (%d)\n", nType);
		return -1;
	}

	nRet = JS_BIN_encodeBase64(pBin, &pBase64);
	if (pBase64 == NULL)
	{
		fprintf(stderr, "fail to encode base64(%d)\n", nRet);
		return -1;
	}

	nHeaderLen = strlen(sHeader);
	nTailLen = strlen(sTail);
	nDelimLen = strlen(pDelim);
	nBase64Len = strlen(pBase64);
	nDelimCount = ( nBase64Len / 64) + 1;

//	pPEM = (char *)M_malloc(nBase64Len + nDelimLen * nDelimCount);
	pPEM = (char *)JS_calloc(1, nHeaderLen + nTailLen + nBase64Len + nDelimLen * nDelimCount + 6 );

	memcpy(pPEM + nPos, sHeader, nHeaderLen );
	nPos += nHeaderLen;

	memcpy(pPEM + nPos, pDelim, nDelimLen);
	nPos += nDelimLen;

	for (int i = 0; i < nDelimCount; i++)
	{
		if (nBase64Pos + 64 < nBase64Len)
			nSize = 64;
		else
			nSize = nBase64Len - nBase64Pos;

		memcpy(pPEM + nPos, pBase64 + nBase64Pos, nSize );

		nBase64Pos += nSize;
		nPos += nSize;

		memcpy(pPEM + nPos, pDelim, nDelimLen);
		nPos += nDelimLen;
	}

	memcpy(pPEM + nPos, sTail, nTailLen);
	nPos += nTailLen;

	memcpy(pPEM + nPos, pDelim, nDelimLen);
	nPos += nDelimLen;

	*ppPEM = pPEM;

	if (pBase64) JS_free(pBase64);


	return 0;
}

int JS_BIN_decodePEM( const char *pPEM, int *pType, BIN *pBin )
{
	int			nRet = 0;
	char		*pBase64 = NULL;
	const char	*pDelim = "\r\n";
	char		sHeader[128];
	char		sTail[128];

	int			bBegin = 0;
	int			bEnd = 0;
	int			nPEMLen = 0;
	int			nPos = 0;
	int			k = 0;

	if (pPEM == NULL) return -1;

	memset(sHeader, 0x00, sizeof(sHeader));
	memset(sTail, 0x00, sizeof(sTail));

	nPEMLen = strlen(pPEM);
	pBase64 = (char *)JS_calloc(1, nPEMLen);

	nPos = _getHeaderLine(pPEM + nPos, sHeader);
	if (nPos < 0) return -1;

	for (int i = 0; i < nPEMLen; i++)
	{
		if (pPEM[nPos] == '\r' || pPEM[nPos] == '\n')
		{
			nPos++;
			continue;
		}

		if (pPEM[nPos] == '-') break;

		pBase64[k] = pPEM[nPos];
		nPos++;
		k++;
	}

	nPos = _getHeaderLine(pPEM + nPos, sTail);
	if (nPos < 0)
	{
		if (pBase64) JS_free(pBase64);
		return -1;
	}

	if (strcasecmp(sHeader, "-----BEGIN RSA PRIVATE KEY-----") == 0)
		*pType = JS_PEM_TYPE_RSA_PRIVATE_KEY;
	else if (strcasecmp(sHeader, "-----BEGIN RSA PUBLIC KEY-----") == 0)
		*pType = JS_PEM_TYPE_RSA_PUBLIC_KEY;
	else if (strcasecmp(sHeader, "-----BEGIN CERTIFICATE REQUEST-----") == 0)
		*pType = JS_PEM_TYPE_CSR;
	else if (strcasecmp(sHeader, "-----BEGIN CERTIFICATE-----") == 0)
		*pType = JS_PEM_TYPE_CERTIFICATE;
	else if (strcasecmp(sHeader, "-----BEGIN X509 CRL-----") == 0)
		*pType = JS_PEM_TYPE_CRL;
	else if (strcasecmp(sHeader, "-----BEGIN PRIVATE KEY-----") == 0)
		*pType = JS_PEM_TYPE_PRIVATE_KEY;
	else if (strcasecmp(sHeader, "-----BEGIN PUBLIC KEY-----") == 0)
		*pType = JS_PEM_TYPE_PUBLIC_KEY;
	else if (strcasecmp(sHeader, "-----BEGIN ENCRYPTED PRIVATE KEY-----") == 0)
		*pType = JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;
	else
		*pType = -1;

	JS_BIN_decodeBase64(pBase64, pBin);
	if (pBase64) JS_free(pBase64);

	return 0;
}

int JS_BIN_encodeBase64URL( const BIN *pBin, char **ppBase64URL )
{
	int nRet = -1;
	int nLen = 0;
	char *pData = NULL;

	if (pBin == NULL || pBin->nLen <= 0) return -1;

	nRet = JS_BIN_encodeBase64(pBin, &pData);
	if (nRet != 0 || pData == NULL )
	{
		if (pData) JS_free(pData);
		return -1;
	}

	nLen = strlen(pData);

	for (int i = 0; i < nLen; i++)
	{
		if (pData[i] == '+') pData[i] = '-';
		if (pData[i] == '/') pData[i] = '_';
		if (pData[i] == '=') pData[i] = 0x00;
	}

	*ppBase64URL = pData;

	return 0;
}

int JS_BIN_decodeBase64URL( const char *pBase64URL, BIN *pBin )
{
	int nRet = 0;
	char *pData = NULL;
	int nLen = 0;
	int nLeft = 0;

	if (pBase64URL == NULL || pBin == NULL) return -1;

	nLen = strlen(pBase64URL);

	pData = (char *)JS_calloc(nLen + 4, 1);
	memcpy(pData, pBase64URL, nLen);

	for (int i = 0; i < nLen; i++)
	{
		if (pData[i] == '_') pData[i] = '/';
		if (pData[i] == '-') pData[i] = '+';
	}

	nLeft = nLen % 4;
	for (int k = nLeft; k < 4; k++)
	{
		pData[nLen + k] = '=';
	}

	nRet = JS_BIN_decodeBase64(pData, pBin);
	if (pData) JS_free(pData);
	
	return 0;
}
