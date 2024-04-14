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
    JS_FILE_TYPE_REQ,
    JS_FILE_TYPE_LCN,
    JS_FILE_TYPE_ALL };

const QColor kAddrColor( 220, 220, 250 );
const QColor kTextColor( 225, 225, 225 );
const QColor kValueColor( 245, 245, 203 );
const QColor kTagColor( 102, 255, 102 );
const QColor kLenColor( 240, 214, 255 );
const QColor kLenTypeColor( Qt::cyan );

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
QString findFolder( QWidget *parent, const QString strPath );

int setOIDList( const QString& strOIDPath );
QString getHexString( const QString& strVal );
QString getHexString( unsigned char *pData, int nDataLen );
QString getHexString( const BIN *pData );
QString getHexView( const char *pName, const BIN *pBin );

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth = -1 );
const QString getHexStringArea( const BIN *pData, int nWidth = -1 );
const QString getHexStringArea( const QString strMsg, int nWidth = -1);

int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );
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

int getDataFromURI( const QString strURI, BIN *pData );
int checkOCSP( const QString strURL, const BIN *pCA, const BIN *pCert, JCertStatusInfo* pStatusInfo);

#endif // COMMON_H
