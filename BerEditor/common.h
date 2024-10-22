/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QWidget>
#include "js_bin.h"
#include "js_pki_x509.h"
#include "js_ocsp.h"

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_BASE64URL,
    DATA_URL
};

enum {
    ENC_ENCRYPT,
    ENC_DECRYPT
};

enum {
    SIGN_SIGNATURE,
    SIGN_VERIFY
};

enum {
    JS_FILE_TYPE_CERT,
    JS_FILE_TYPE_CRL,
    JS_FILE_TYPE_CSR,
    JS_FILE_TYPE_PRIKEY,
    JS_FILE_TYPE_TXT,
    JS_FILE_TYPE_BER,
    JS_FILE_TYPE_CFG,
    JS_FILE_TYPE_PFX,
    JS_FILE_TYPE_BIN,
    JS_FILE_TYPE_LCN,
    JS_FILE_TYPE_JSON,
    JS_FILE_TYPE_PKCS7,
    JS_FILE_TYPE_ALL };

const QColor kAddrColor( 220, 220, 250 );
const QColor kTextColor( 225, 225, 225 );
const QColor kValueColor( 245, 245, 203 );
const QColor kTagColor( 102, 255, 102 );
const QColor kLenColor( 240, 214, 255 );
const QColor kLenTypeColor( Qt::cyan );


#define VIEW_FILE                   0x01000000
#define VIEW_EDIT                   0x02000000
#define VIEW_TOOL                   0x03000000
#define VIEW_CRYPT                  0x04000000
#define VIEW_PROTO                  0x05000000
#define VIEW_KMIP                   0x06000000
#define VIEW_HELP                   0x07000000

#define ACT_FILE_NEW                VIEW_FILE | 0x00000001
#define ACT_FILE_OPEN               VIEW_FILE | 0x00000002
#define ACT_FILE_OPEN_CERT          VIEW_FILE | 0x00000004
#define ACT_FILE_OPEN_CRL           VIEW_FILE | 0x00000008
#define ACT_FILE_OPEN_CSR           VIEW_FILE | 0x00000010
#define ACT_FILE_OPEN_PRI_KEY       VIEW_FILE | 0x00000020
#define ACT_FILE_OPEN_PUB_KEY       VIEW_FILE | 0x00000040
#define ACT_FILE_OPEN_CMS           VIEW_FILE | 0x00000080
#define ACT_FILE_SAVE               VIEW_FILE | 0x00000100
#define ACT_FILE_SAVE_AS            VIEW_FILE | 0x00000200
#define ACT_FILE_PRINT              VIEW_FILE | 0x00000400
#define ACT_FILE_PRINT_PREVEIW      VIEW_FILE | 0x00000800
#define ACT_FILE_QUIT               VIEW_FILE | 0x00001000

#define ACT_EDIT_COPY_INFO          VIEW_EDIT | 0x00000001
#define ACT_EDIT_COPY_AS_HEX        VIEW_EDIT | 0x00000002
#define ACT_EDIT_COPY_AS_BASE64     VIEW_EDIT | 0x00000004
#define ACT_EDIT_EXPAND_ALL         VIEW_EDIT | 0x00000008
#define ACT_EDIT_EXPAND_NODE        VIEW_EDIT | 0x00000010
#define ACT_EDIT_COLLAPSE_ALL       VIEW_EDIT | 0x00000020
#define ACT_EDIT_COLLAPSE_NODE      VIEW_EDIT | 0x00000040

#define ACT_TOOL_DATA_ENCODER       VIEW_TOOL | 0x00000001
#define ACT_TOOL_NUM_TRANS          VIEW_TOOL | 0x00000002
#define ACT_TOOL_OID_INFO           VIEW_TOOL | 0x00000004
#define ACT_TOOL_MAKE_BER           VIEW_TOOL | 0x00000008
#define ACT_TOOL_DECODE_DATA        VIEW_TOOL | 0x00000010
#define ACT_TOOL_GET_URI            VIEW_TOOL | 0x00000020

#define ACT_CRYPT_KEY_MAN           VIEW_CRYPT | 0x00000001
#define ACT_CRYPT_HASH              VIEW_CRYPT | 0x00000002
#define ACT_CRYPT_MAC               VIEW_CRYPT | 0x00000004
#define ACT_CRYPT_ENC_DEC           VIEW_CRYPT | 0x00000008
#define ACT_CRYPT_SIGN_VERIFY       VIEW_CRYPT | 0x00000010
#define ACT_CRYPT_PUB_ENC           VIEW_CRYPT | 0x00000020
#define ACT_CRYPT_KEY_AGREE         VIEW_CRYPT | 0x00000040
#define ACT_CRYPT_CMS               VIEW_CRYPT | 0x00000080
#define ACT_CRYPT_SSS               VIEW_CRYPT | 0x00000100
#define ACT_CRYPT_CERT_PVD          VIEW_CRYPT | 0x00000200
#define ACT_CRYPT_OTP_GEN           VIEW_CRYPT | 0x00000400
#define ACT_CRYPT_VID               VIEW_CRYPT | 0x00000800
#define ACT_CRYPT_BN_CALC           VIEW_CRYPT | 0x00001000
#define ACT_CRYPT_KEY_PAIR_MAN      VIEW_CRYPT | 0x00002000
#define ACT_CRYPT_CERT_MAN          VIEW_CRYPT | 0x00004000
#define ACT_CRYPT_CAVP              VIEW_CRYPT | 0x00008000
#define ACT_CRYPT_SSL_VERIFY        VIEW_CRYPT | 0x00010000

#define ACT_PROTO_OCSP              VIEW_PROTO | 0x00000001
#define ACT_PROTO_TSP               VIEW_PROTO | 0x00000002
#define ACT_PROTO_CMP               VIEW_PROTO | 0x00000004
#define ACT_PROTO_SCEP              VIEW_PROTO | 0x00000008

#define ACT_KMIP_DECODE_TTLV        VIEW_KMIP | 0x00000001
#define ACT_KMIP_MAKE_TTLV          VIEW_KMIP | 0x00000002
#define ACT_KMIP_ENCODE_TTLV        VIEW_KMIP | 0x00000004
#define ACT_KMIP_CLIENT_TTLV        VIEW_KMIP | 0x00000008

#define ACT_HELP_SETTINGS           VIEW_HELP | 0x00000001
#define ACT_HELP_CLEAR_LOG          VIEW_HELP | 0x00000002
#define ACT_HELP_HALT_LOG           VIEW_HELP | 0x00000004
#define ACT_HELP_CONTENT            VIEW_HELP | 0x00000008
#define ACT_HELP_LICENSE_INFO       VIEW_HELP | 0x00000010
#define ACT_HELP_BUG_REPORT         VIEW_HELP | 0x00000020
#define ACT_HELP_QNA                VIEW_HELP | 0x00000040
#define ACT_HELP_ABOUT              VIEW_HELP | 0x00000080

static const int kFileDefault = ACT_FILE_NEW | ACT_FILE_OPEN | ACT_FILE_SAVE;

static const int kEditDefault = ACT_EDIT_EXPAND_ALL | ACT_EDIT_EXPAND_NODE | ACT_EDIT_COLLAPSE_ALL \
                         | ACT_EDIT_COLLAPSE_NODE;

static const int kToolDefault = ACT_TOOL_DATA_ENCODER | ACT_TOOL_OID_INFO | ACT_TOOL_MAKE_BER \
                         | ACT_TOOL_DECODE_DATA | ACT_TOOL_GET_URI;

static const int kCryptDefault = ACT_CRYPT_HASH | ACT_CRYPT_MAC | ACT_CRYPT_ENC_DEC \
                          | ACT_CRYPT_SIGN_VERIFY | ACT_CRYPT_PUB_ENC | ACT_CRYPT_KEY_AGREE \
                          | ACT_CRYPT_CERT_PVD | ACT_CRYPT_BN_CALC | ACT_CRYPT_KEY_PAIR_MAN \
                          | ACT_CRYPT_CERT_MAN | ACT_CRYPT_SSL_VERIFY;

static const int kProtoDefault = 0;
static const int kKMIPDefault = 0;
static const int kHelpDefault = ACT_HELP_CLEAR_LOG | ACT_HELP_HALT_LOG | ACT_HELP_CONTENT | ACT_HELP_ABOUT;


const QStringList kECCParamList = {
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "prime256v1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1", "SM2"
};

static QStringList kHashList = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3"
};


static const QString kSettingBer = "SettingBer";

static QStringList kValueTypeList = { "String", "Hex", "Base64" };

const QString kExtNameAIA = "authorityInfoAccess";
const QString kExtNameAKI = "authorityKeyIdentifier";
const QString kExtNameBC = "basicConstraints";
const QString kExtNameCRLDP = "crlDistributionPoints";
const QString kExtNameEKU = "extendedKeyUsage";
const QString kExtNameIAN = "issuerAltName";
const QString kExtNameKeyUsage = "keyUsage";
const QString kExtNameNC = "nameConstraints";
const QString kExtNamePolicy = "certificatePolicies";
const QString kExtNamePC = "policyConstraints";
const QString kExtNamePM = "policyMappings";
const QString kExtNameSKI = "subjectKeyIdentifier";
const QString kExtNameSAN = "subjectAltName";
const QString kExtNameCRLNum = "crlNumber";
const QString kExtNameIDP = "issuingDistributionPoint";
const QString kExtNameCRLReason = "CRLReason";
const int kNoLicenseLimitMaxSize = 10000;

const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

const QString GetSystemID();

QString findFile( QWidget *parent, int nType, const QString strPath );
QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected );
QString findSaveFile( QWidget *parent, int nType, const QString strPath );
QString findFolder( QWidget *parent, const QString strPath );

int setOIDList( const QString& strOIDPath );
QString getHexString( const QString& strVal );
QString getHexString( unsigned char *pData, int nDataLen );
QString getHexString( const BIN *pData );
QString getHexString2( const BIN *pData );
QString getHexView( const char *pName, const BIN *pBin );

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth = -1 );
const QString getHexStringArea( const BIN *pData, int nWidth = -1 );
const QString getHexStringArea( const QString strMsg, int nWidth = -1);

int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );
const QString getDataLenString( int nType, const QString strData );
const QString getDataLenString( const QString strType, const QString strData );

QString getSymAlg( const QString strAlg, const QString strMode, int nKeyLen );
int getNameValue( const QString strLine, QString& name, QString& value );

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal, bool bShow = true );
const QString getExtValue( const QString strName, const QString strHexValue, bool bShow = true );

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString );
void getBINFromString( BIN *pBin, int nType, const QString& strString );
QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly = false );
QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly = false );
QString getKeyTypeName( int nKeyType );

bool isValidNumFormat( const QString strInput, int nNumber );

bool isEmail( const QString strEmail );
bool isHex( const QString strHexString );
bool isBase64( const QString strBase64String );
bool isBase64URL( const QString strBase64URLString );
bool isURLEncode( const QString strURLEncode );

int getDataFromURI( const QString strURI, BIN *pData );
int checkOCSP( const QString strURL, const BIN *pCA, const BIN *pCert, JCertStatusInfo* pStatusInfo);

#endif // COMMON_H
