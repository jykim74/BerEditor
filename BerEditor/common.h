/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QWidget>
#include <QLineEdit>

#include "js_bin.h"
#include "js_pki_x509.h"
#include "js_ocsp.h"
#include "js_pki.h"
#include "js_pqc.h"
#include "js_pki_raw.h"

enum {
    DATA_HEX,
    DATA_STRING,
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
    JS_FILE_TYPE_XML,
    JS_FILE_TYPE_PKCS7,
    JS_FILE_TYPE_PKCS8,
    JS_FILE_TYPE_PRIKEY_PKCS8_PFX,
    JS_FILE_TYPE_DH_PARAM,
    JS_FILE_TYPE_ALL };

const QString kDataHex = "Hex";
const QString kDataString = "String";
const QString kDataBase64 = "Base64";
const QString kDataURL = "URL";
const QString kDataBase64URL = "Base64URL";

const QStringList kDataTypeList = { kDataHex, kDataString, kDataBase64 };
const QStringList kDataTypeList2 = { kDataHex, kDataString, kDataBase64, kDataURL, kDataBase64URL };
const QStringList kDataBinTypeList = { kDataHex, kDataBase64 };

const QString kEnvMiscGroup = "Misc";
const QString kEnvTempGroup = "Temp";

const QColor kAddrColor( 220, 220, 250 );
const QColor kTextColor( 225, 225, 225 );
const QColor kValueColor( 245, 245, 203 );
const QColor kTagColor( 102, 255, 102 );
const QColor kLenColor( 240, 214, 255 );
const QColor kLenTypeColor( Qt::cyan );
const QColor kEOCColor( 177, 188, 199 );
const QColor kUnusedColor( 199, 210, 200 );

const QString kBinaryChars = "[0-1]";
const QString kHexChars = "[A-Za-f0-9]";
const QString kDecimalChars = "[0-9]";

const QString kAlgRSA = "RSA";
const QString kAlgECDSA = "ECDSA";
const QString kAlgSM2 = "SM2";
const QString kAlgDSA = "DSA";
const QString kAlgEdDSA = "EdDSA";

static QString kSelectStyle =
    "QTableWidget::item:selected { "
    "background-color: #9370db; "
    "color: white; "
    "} ";

#define TOOL_BAR_WIDTH      24
#define TOOL_BAR_HEIGHT     24


#define VIEW_FILE                   0x01000000
#define VIEW_EDIT                   0x02000000
#define VIEW_TOOL                   0x03000000
#define VIEW_CRYPT                  0x04000000
#define VIEW_SERVICE                0x05000000
#define VIEW_PROTO                  0x06000000
#define VIEW_KMIP                   0x07000000
#define VIEW_HELP                   0x08000000

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
#define ACT_EDIT_PREV_NODE          VIEW_EDIT | 0x00000080
#define ACT_EDIT_NEXT_NODE          VIEW_EDIT | 0x00000100
#define ACT_EDIT_FIND_NODE          VIEW_EDIT | 0x00000200

#define ACT_TOOL_DATA_CONVERTER     VIEW_TOOL | 0x00000001
#define ACT_TOOL_NUM_CONVERTER      VIEW_TOOL | 0x00000002
#define ACT_TOOL_OID_INFO           VIEW_TOOL | 0x00000004
#define ACT_TOOL_MAKE_BER           VIEW_TOOL | 0x00000008
#define ACT_TOOL_BER_CHECK          VIEW_TOOL | 0x00000010
#define ACT_TOOL_DECODE_DATA        VIEW_TOOL | 0x00000020
#define ACT_TOOL_GET_URI            VIEW_TOOL | 0x00000040

#define ACT_CRYPT_KEY_MAN           VIEW_CRYPT | 0x00000001
#define ACT_CRYPT_HASH              VIEW_CRYPT | 0x00000002
#define ACT_CRYPT_MAC               VIEW_CRYPT | 0x00000004
#define ACT_CRYPT_ENC_DEC           VIEW_CRYPT | 0x00000008
#define ACT_CRYPT_SIGN_VERIFY       VIEW_CRYPT | 0x00000010
#define ACT_CRYPT_PUB_ENC           VIEW_CRYPT | 0x00000020
#define ACT_CRYPT_KEY_AGREE         VIEW_CRYPT | 0x00000040
#define ACT_CRYPT_PKCS7             VIEW_CRYPT | 0x00000080
#define ACT_CRYPT_SSS               VIEW_CRYPT | 0x00000100
#define ACT_CRYPT_CERT_PVD          VIEW_CRYPT | 0x00000200
#define ACT_CRYPT_OTP_GEN           VIEW_CRYPT | 0x00000400
#define ACT_CRYPT_VID               VIEW_CRYPT | 0x00000800
#define ACT_CRYPT_BN_CALC           VIEW_CRYPT | 0x00001000

#define ACT_SERVICE_KEY_PAIR_MAN    VIEW_SERVICE | 0x00000001
#define ACT_SERVICE_CERT_MAN        VIEW_SERVICE | 0x00000002
#define ACT_SERVICE_SSL_CHECK       VIEW_SERVICE | 0x00000004
#define ACT_SERVICE_KEY_LIST        VIEW_SERVICE | 0x00000008
#define ACT_SERVICE_X509_COMP       VIEW_SERVICE | 0x00000010
#define ACT_SERVICE_DOC_SIGNER      VIEW_SERVICE | 0x00000020
#define ACT_SERVICE_CAVP            VIEW_SERVICE | 0x00000040

#define ACT_PROTO_OCSP              VIEW_PROTO | 0x00000001
#define ACT_PROTO_TSP               VIEW_PROTO | 0x00000002
#define ACT_PROTO_CMP               VIEW_PROTO | 0x00000004
#define ACT_PROTO_SCEP              VIEW_PROTO | 0x00000008
#define ACT_PROTO_ACME              VIEW_PROTO | 0x00000010

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

#define FORMAT_WARN_GO(x) if( x < 0 ) \
{ \
    berApplet->formatWarn( x, this ); \
    goto end; \
}

#define FORMAT_WARN_RET(x) if( x < 0 ) \
{ \
    berApplet->formatWarn( x, this ); \
    return x; \
}

static const int kFileDefault = ACT_FILE_NEW | ACT_FILE_OPEN;

static const int kEditDefault = ACT_EDIT_EXPAND_ALL | ACT_EDIT_EXPAND_NODE | ACT_EDIT_PREV_NODE | ACT_EDIT_NEXT_NODE | ACT_EDIT_FIND_NODE;

static const int kToolDefault = ACT_TOOL_DATA_CONVERTER | ACT_TOOL_OID_INFO | ACT_TOOL_MAKE_BER \
                         | ACT_TOOL_DECODE_DATA | ACT_TOOL_GET_URI;

static const int kCryptDefault = ACT_CRYPT_HASH | ACT_CRYPT_MAC | ACT_CRYPT_ENC_DEC \
                          | ACT_CRYPT_SIGN_VERIFY | ACT_CRYPT_CERT_PVD | ACT_CRYPT_BN_CALC;

static const int kServiceDefault = ACT_SERVICE_KEY_PAIR_MAN | ACT_SERVICE_CERT_MAN | \
                                   ACT_SERVICE_KEY_LIST | ACT_SERVICE_SSL_CHECK | ACT_SERVICE_X509_COMP;

static const int kProtoDefault = ACT_PROTO_ACME;
static const int kKMIPDefault = 0;
static const int kHelpDefault = ACT_HELP_ABOUT;

// const QStringList kSymAlgList = { JS_PKI_KEY_NAME_AES, JS_PKI_KEY_NAME_ARIA, JS_PKI_KEY_NAME_SEED, JS_PKI_KEY_NAME_SM4, JS_PKI_KEY_NAME_TDES };

const QStringList kBaseSymList = {
    "AES",
    "ARIA"
};

const QStringList kSymAlgList = {
    JS_PKI_KEY_NAME_AES,
    JS_PKI_KEY_NAME_ARIA,
    JS_PKI_KEY_NAME_SM4,
    JS_PKI_KEY_NAME_SEED
};

const QString kSymGeneric = "Generic";

const QStringList kRSAOptionList = { "1024", "2048", "3072", "4096", "8192" };

const QStringList kECDSAOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1"
};

const QStringList kEdDSAOptionList = { JS_EDDSA_PARAM_NAME_25519, JS_EDDSA_PARAM_NAME_448 };

const QStringList kDSAOptionList = { "1024", "2048", "3072" };
const QStringList kDHOptionList = { "1024", "2048", "3072", "4096" };

const QStringList kML_KEMOptionList = {
    JS_PQC_PARAM_ML_KEM_512_NAME,
    JS_PQC_PARAM_ML_KEM_768_NAME,
    JS_PQC_PARAM_ML_KEM_1024_NAME
};

const QStringList kML_DSAOptionList = {
    JS_PQC_PARAM_ML_DSA_44_NAME,
    JS_PQC_PARAM_ML_DSA_65_NAME,
    JS_PQC_PARAM_ML_DSA_87_NAME
};

const QStringList kSLH_DSAOptionList = {
    JS_PQC_PARAM_SLH_DSA_SHA2_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256F_NAME
};

static QStringList kHashList = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "MD5"
};

static QStringList kSHAHashList = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512"
};

static QStringList kSHA12HashList = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
};

static QStringList kPBEList = {
    "AES-128-CBC", "AES-256-CBC", "ARIA-128-CBC", "ARIA-256-CBC",   // Version2
    "PBE-SHA1-3DES", "PBE-SHA1-2DES"                                // Version1
};

static int kIterCnt = 1024;
static QString kSalt = "BerEditor";

static const QString kSettingBer = "SettingBer";

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

const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}\n"
                            "QHeaderView::section:selected {background-color:#404040;}\n"
                            "QHeaderView::section:pressed {background-color:#404040;}";

const QString kReadOnlyStyle = "background-color:#ddddff";
const QString kDisableStyle = "background-color:#cccccc";

const QString GetSystemID();

int setOIDList( const QString& strOIDPath );
QString getHexString( const QString& strVal );
QString getHexString( unsigned char *pData, int nDataLen );
QString getHexString( const BIN *pData );
QString getHexString2( const BIN *pData );
QString getHexView( const char *pName, const BIN *pBin );
QString getBase64URL_FromHex( const QString strHex );
QString getHex_FromBase64URL( const QString strBase64URL );

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth = -1 );
const QString getHexStringArea( const BIN *pData, int nWidth = -1 );
const QString getHexStringArea( const QString strMsg, int nWidth = -1);

int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );
const QString getDataLenString( int nType, const QString strData );
const QString getDataLenString( const QString strType, const QString strData );

int getSymAlg( const QString strAlg, const QString strMode, int nKeyLen, QString& strCipher );
int getNameValue( const QString strLine, QString& name, QString& value );

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal, bool bShow = true );
const QString getExtValue( const QString strName, const QString strHexValue, bool bShow = true );

int getBINFromString( BIN *pBin, const QString& strType, const QString& strString );
int getBINFromString( BIN *pBin, int nType, const QString& strString );
QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly = false );
QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly = false );

bool isValidNumFormat( const QString strInput, int nNumber );

bool isEmail( const QString strEmail );
bool isHTTP( const QString strURL );
bool isHex( const QString strHexString );
bool isBase64( const QString strBase64String );
bool isBase64URL( const QString strBase64URLString );
bool isURLEncode( const QString strURLEncode );

int getDataFromURI( const QString strURI, BIN *pData );
int checkOCSP( const QString strURL, const BIN *pCA, const BIN *pCert, JCertStatusInfo* pStatusInfo);

int getWrapKey( const char *pPasswd, const BIN *pKey, BIN *pEncKey );
int getUnwrapKey( const char *pPasswd, const BIN *pEncKey, BIN *pKey );
int getDigestLength( const QString strHash );

const QString getMS( qint64 time );

int writePriKeyPEM( const BIN *pPriKey, const QString strPath );
int writePubKeyPEM( const BIN *pPubKey, const QString strPath );

const QString encodeBase64( const QString strString );
const QString decodeBase64( const QString strBase64 );

void setFixedLineText( QLineEdit *pEdit, const QString strText );
void setLineEditHexOnly( QLineEdit *pEdit, const QString strPlaceHolder = "" );

#endif // COMMON_H
