/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QString>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QRegExp>
#include <QProcess>
#include <QNetworkInterface>

#include "common.h"
#include "js_ocsp.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "js_http.h"
#include "js_ldap.h"
#include "js_scep.h"

const QString GetSystemID()
{
    QString strID;

#ifdef Q_OS_MACOS
    QProcess proc;
    QStringList args;
    args << "-c" << "ioreg -rd1 -c IOPlatformExpertDevice |  awk '/IOPlatformSerialNumber/ { print $3; }'";
    proc.start( "/bin/bash", args );
    proc.waitForFinished();
    QString uID = proc.readAll();
    uID.replace( "\"", "" );

    strID = uID.trimmed();
#else

    foreach( QNetworkInterface netIFT, QNetworkInterface::allInterfaces() )
    {
        if( !(netIFT.flags() & QNetworkInterface::IsLoopBack) )
        {
            if( netIFT.flags() & QNetworkInterface::IsUp )
            {
                if( netIFT.flags() & QNetworkInterface::Ethernet || netIFT.flags() & QNetworkInterface::Wifi )
                {
                    if( strID.isEmpty() )
                        strID = netIFT.hardwareAddress();
                    else
                    {
                        strID += QString( "|%1" ).arg( netIFT.hardwareAddress() );
                    }
                }
            }
        }
    }
#endif

    return strID;
}

static const QString _getFileFilter( int nType )
{
    QString strFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strFilter = QObject::tr("Cert Files (*.crt *.der *.cer *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_CRL )
        strFilter = QObject::tr("CRL Files (*.crl *.der *.cer *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_CSR )
        strFilter = QObject::tr("CSR Files (*.csr *.der *.cer *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strFilter = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strFilter = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strFilter = QObject::tr("BER Files (*.der *.pem *.cer *.crt *.crl *.csr);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_CFG )
        strFilter = QObject::tr("Config Files (*.cfg *.ini);;All Files(*.*)" );
    else if( nType == JS_FILE_TYPE_REQ )
        strFilter = QObject::tr("Req Files (*.req *.txt);;All Files(*.*)" );
    else if( nType == JS_FILE_TYPE_PFX )
        strFilter = QObject::tr("PFX Files (*.pfx *.p12);;All Files(*.*)" );
    else if( nType == JS_FILE_TYPE_LCN )
        strFilter = QObject::tr( "License Files (*.lcn *.txt);;All Files (*.*)" );
    else
        strFilter = QObject::tr("All Files(*.*)" );

    return strFilter;
}

QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    QString strFilter = _getFileFilter( nType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};



QString findSaveFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    //    QString strPath = QDir::currentPath();

    QString strFilter = _getFileFilter( nType );
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save File" ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    return fileName;
};

QString findFolder( QWidget *parent, const QString strPath )
{
    QFileDialog::Options options;
    options |= QFileDialog::ShowDirsOnly;
    options |= QFileDialog::DontResolveSymlinks;


    QString folderName = QFileDialog::getExistingDirectory(
                parent, QObject::tr("Open Directory"), strPath, options);

    return folderName;
}

int setOIDList( const QString& strOIDPath )
{
    int ret = 0;
    int nCount = 0;


    QString strOID;
    QString strSN;
    QString strLN;

    QFile file( strOIDPath );

    if( !file.open(QIODevice::ReadOnly | QIODevice::Text))
        return -1;

    QTextStream in( &file );
    QString line = in.readLine();

    while( 1 )
    {
        QString strName;
        QString strVal;

        if( line.length() == 0 || line.isNull() )
        {
            if( strOID.length() > 0 && strSN.length() > 0 )
            {
                if( strLN.length() < 1 ) strLN = strSN;
                ret = JS_PKI_createOID( strOID.toStdString().c_str(), strSN.toStdString().c_str(), strLN.toStdString().c_str() );
                if( ret > 0 ) nCount++;
            }

            strOID.clear();
            strSN.clear();
            strLN.clear();

            if( line.isNull() ) break;

            line = in.readLine();
            continue;
        }

        if( line.at(0) == '#' )
        {
            line = in.readLine();
            continue;
        }

        QStringList nameVal = line.split( "=" );
        if( nameVal.size() != 2 )
        {
            continue;
        }

        strName = nameVal.at(0).trimmed();
        strVal = nameVal.at(1).trimmed();

        if( strName == "OID" )
            strOID = strVal;
        else if( strName == "SN" )
            strSN = strVal;
        else if( strName == "LN" )
            strLN = strVal;

        line = in.readLine();
    }

    file.close();
    JS_SCEP_init();
    return nCount;
}

QString getHexString( const QString& strVal )
{
    char *pHex = NULL;
    BIN binVal = {0,0};
    QString strHex;

    JS_BIN_set( &binVal, (unsigned char *)strVal.toStdString().c_str(), strVal.length() );
    JS_BIN_encodeHex( &binVal, &pHex );

    if( pHex )
    {
        strHex = pHex;
        JS_free( pHex );
    }

    return strHex;
}

QString getHexString( unsigned char *pData, int nDataLen )
{
    BIN binData = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binData, pData, nDataLen );
    JS_BIN_encodeHex( &binData, &pHex );

    QString strHex = pHex;

    JS_BIN_reset( &binData );
    if(pHex) JS_free( pHex );

    return strHex;
}

QString getHexString( const BIN *pData )
{
    if( pData == NULL ) return "";

    return getHexString( pData->pVal, pData->nLen );
}

static char _getPrint( unsigned char c )
{
    if( isprint(c))
      return c;
    else
      return '.';
}

QString getHexView( const char *pName, const BIN *pBin )
{
    int n = 0;
    int left = 0;
    char  sText[16 + 1];
    int length = 0;
    unsigned char *packet = NULL;

    QString strOut;
    QString strTmp;

    if( pName ) strOut += QString( "-- %1 --\n" ).arg( pName );

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    length = pBin->nLen;
    packet = pBin->pVal;

    memset( sText, 0x00, sizeof(sText));

    while (length--)
    {
        if (n % 16 == 0)
        {
            strTmp = QString( "%1 ").arg( n, 8, 16, QLatin1Char('0')).toUpper();
            strOut += strTmp;
        }

        sText[n%16] = _getPrint( *packet );
        strTmp = QString( "%1 " ).arg( *packet++, 2, 16, QLatin1Char('0')).toUpper();
        strOut += strTmp;

        n++;
        if (n % 8 == 0)
        {
            if (n % 16 == 0)
            {
                strTmp = QString( " %1\n" ).arg( sText );
                strOut += strTmp;
                memset( sText, 0x00, sizeof(sText));
            }
            else
            {
                strTmp = QString(" ");
                strOut += strTmp;
            }
        }
    }

    left = n % 16;
    if( left > 0 )
    {
        for( int i = left; i < 16; i++ )
        {
            strTmp = QString( "   " );
            strOut += strTmp;
        }

        if( left < 8 )
        {
            strTmp = QString( " " );
            strOut += strTmp;
        }

        strTmp = QString( "  %1\n").arg( sText );
        strOut += strTmp;
    }

    return strOut;
}

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth  )
{
    QString strMsg = getHexString( pData, nDataLen );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const BIN *pData, int nWidth )
{
    QString strMsg = getHexString( pData );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const QString strMsg, int nWidth )
{
    int nBlock = 0;
    int nPos = 0;
    QString strAreaMsg = nullptr;

    int nLen = strMsg.length();
    if( nWidth <= 0 ) return strMsg;

    while( nLen > 0 )
    {
        if( nLen >= nWidth )
            nBlock = nWidth;
        else
            nBlock = nLen;

        strAreaMsg += strMsg.mid( nPos, nBlock );
        strAreaMsg += "\n";

        nLen -= nBlock;
        nPos += nBlock;
    }

    return strAreaMsg;
}

int getDataLen( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;


    if( nType != DATA_STRING )
    {
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        nLen = strMsg.length() / 2;

        if( strMsg.length() % 2 ) nLen++;

        return nLen;
    }
    else if( nType == DATA_BASE64 )
    {
        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );
        return nLen;
    }

    return strData.length();
}

int getDataLen( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;

    return getDataLen( nType, strData );
}

QString getSymAlg( const QString strAlg, const QString strMode, int nKeyLen )
{
    QString strRes;
    strRes.clear();

    QString strLAlg = strAlg.toLower();
    QString strLMode = strMode.toLower();

    if( (nKeyLen % 8) != 0 ) return strRes;
    if( nKeyLen > 32 ) return strRes;

    if( strAlg.isEmpty() || strMode.isEmpty() ) return strRes;

    if( strLAlg == "des" || strLAlg == "seed" || strLAlg == "sm4" )
        strRes = QString( "%1-%2").arg(strLAlg).arg(strLMode );
    else if( strLAlg == "des3" )
        strRes = QString( "des-ede-%1").arg(strLMode);
    else
        strRes = QString( "%1-%2-%3" ).arg( strLAlg ).arg( nKeyLen * 8 ).arg( strLMode);

    return strRes;
}

int getNameValue( const QString strLine, QString& name, QString& value )
{
    if( strLine.isEmpty() ) return -1;

    QStringList nameVal = strLine.split( "=" );

    if( nameVal.size() >= 1 )
        name = nameVal.at(0).trimmed();

    if( nameVal.size() >= 2 )
        value = nameVal.at(1).trimmed();

    return 0;
}


static int _getKeyUsage( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nKeyUsage = 0;

    ret = JS_PKI_getKeyUsageValue( pBinExt, &nKeyUsage );

    if( nKeyUsage & JS_PKI_KEYUSAGE_DIGITAL_SIGNATURE )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DigitalSignature";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_NON_REPUDIATION )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "NonRepudiation";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DATA_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DataEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_AGREEMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyAgreement";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CERT_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "keyCertSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CRL_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "cRLSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_ENCIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "EncipherOnly";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DECIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DecipherOnly";
    }

    return 0;
}

static int _getCRLNum( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pCRLNum = NULL;

    ret = JS_PKI_getCRLNumberValue( pBinExt, &pCRLNum );

    if( pCRLNum ) {
        if(bShow)
            strVal = QString( "CRL Number=%1" ).arg( pCRLNum );
        else
            strVal = pCRLNum;

        JS_free( pCRLNum );
    }

    return 0;
}

static int _getCertPolicy( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 0;
    JExtPolicyList *pPolicyList = NULL;
    JExtPolicyList *pCurList = NULL;

    ret = JS_PKI_getCertificatePoliciesValue( pBinExt, &pPolicyList );

    pCurList = pPolicyList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Certificate Policy:\n" ).arg(i+1);
            strVal += QString( " Policy Identifier=%1\n" ).arg( pCurList->sPolicy.pOID );
            if( pCurList->sPolicy.pCPS )
            {
                strVal += QString( " [%1,1] CPS = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pCPS );
            }

            if( pCurList->sPolicy.pUserNotice )
            {
                strVal += QString( " [%1,2] UserNotice = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pUserNotice );
            }
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString("#OID$%1#CPS$%2#UserNotice$%3")
                .arg( pCurList->sPolicy.pOID )
                .arg( pCurList->sPolicy.pCPS )
                .arg( pCurList->sPolicy.pUserNotice );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pPolicyList ) JS_PKI_resetExtPolicyList( &pPolicyList );
    return 0;
}


static int _getSKI( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char        *pSKI = NULL;

    ret = JS_PKI_getSubjectKeyIdentifierValue( pBinExt, &pSKI );

    if( pSKI )
    {
        strVal = pSKI;
        JS_free( pSKI );
    }

    return 0;
}


static int _getAKI( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pAKI = NULL;
    char    *pIssuer = NULL;
    char    *pSerial = NULL;

    ret = JS_PKI_getAuthorityKeyIdentifierValue( pBinExt, &pAKI, &pIssuer, &pSerial );

    if( bShow == true )
    {
        strVal = QString( "KeyID=%1\n").arg( pAKI );
        if( pIssuer ) strVal += QString( "CertificateIssuer=\n    %1\n").arg( pIssuer );
        if( pSerial ) strVal += QString( "CertificateSerialNumber=%1").arg( pSerial );
    }
    else
    {
        strVal = QString( "KEYID$%1#ISSUER$%2#SERIAL$%3").arg( pAKI ).arg( pIssuer ).arg( pSerial );
    }

    if( pAKI ) JS_free( pAKI );
    if( pIssuer ) JS_free( pIssuer );
    if( pSerial ) JS_free( pSerial );

    return 0;
}

static int _getEKU( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    JStrList   *pEKUList = NULL;
    JStrList   *pCurList = NULL;

    ret = JS_PKI_getExtendedKeyUsageValue( pBinExt, &pEKUList );

    pCurList = pEKUList;

    while( pCurList )
    {
        if( strVal.length() > 0 ) strVal += ",";

        strVal += QString( pCurList->pStr );

        pCurList = pCurList->pNext;
    }

    if( pEKUList ) JS_UTIL_resetStrList( &pEKUList );
    return 0;
}

static int _getCRLDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int i = 1;
    JNameValList   *pCRLDPList = NULL;
    JNameValList    *pCurList = NULL;

    ret = JS_PKI_getCRLDPValue( pBinExt, &pCRLDPList );

    pCurList = pCRLDPList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1] CRL Distribution Point\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( pCurList->sNameVal.pName ).arg( pCurList->sNameVal.pValue );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "#";

            strVal += QString( "%1$%2")
                .arg( pCurList->sNameVal.pName )
                .arg( pCurList->sNameVal.pValue );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pCRLDPList ) JS_UTIL_resetNameValList( &pCRLDPList );
    return 0;
}

static int _getBC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nType = -1;
    int nPathLen = -1;

    QString strType;
    QString strPathLen;

    ret = JS_PKI_getBCValue( pBinExt, &nType, &nPathLen );

    if( nType == JS_PKI_BC_TYPE_CA )
        strType = "CA";
    else if( nType == JS_PKI_BC_TYPE_USER )
        strType = "EE";


    if( nPathLen >= 0 )
        strPathLen = QString("$PathLen:%1").arg( nPathLen );

    if( bShow )
    {
        strVal = QString( "SubjectType=%1\n").arg(strType);
        if( nPathLen >= 0 )
            strVal += QString( "PathLengthConstraint=%1" ).arg(nPathLen);
        else
            strVal += QString( "PathLengthConstraint=None" );
    }
    else
    {
        strVal += strType;
        strVal += strPathLen;
    }

    return 0;
}


static int _getPC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nREP = -1;
    int nIPM = -1;

    ret = JS_PKI_getPolicyConstValue( pBinExt, &nREP, &nIPM );

    if( bShow )
    {
        if( nREP >= 0 ) strVal += QString("RequiredExplicitPolicySkipCerts=%1\n").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("InhibitPolicyMappingSkipCerts=%1\n").arg( nIPM );
    }
    else
    {
        if( nREP >= 0 ) strVal += QString("#REP$%1").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("#IPM$%1").arg( nIPM );
    }

    return 0;
}

static int _getAIA( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;
    JExtAuthorityInfoAccessList    *pAIAList = NULL;
    JExtAuthorityInfoAccessList    *pCurList = NULL;

    ret = JS_PKI_getAuthorityInfoAccessValue( pBinExt, &pAIAList );

    pCurList = pAIAList;

    while( pCurList )
    {
        QString strType = JS_PKI_getGenNameString( pCurList->sAuthorityInfoAccess.nType );

        if( bShow )
        {
            strVal += QString( "[%1]Authority Info Access\n" ).arg(i);
            strVal += QString( " Access Method=%1\n").arg(pCurList->sAuthorityInfoAccess.pMethod);
            strVal += QString( " Alternative Name:\n" );
            strVal += QString( " %1=%2\n" ).arg(strType).arg(pCurList->sAuthorityInfoAccess.pName );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "Method$%1#Type$%2#Name$%3")
                .arg( pCurList->sAuthorityInfoAccess.pMethod )
                .arg( strType )
                .arg( pCurList->sAuthorityInfoAccess.pName );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pAIAList ) JS_PKI_resetExtAuthorityInfoAccessList( &pAIAList );
    return 0;
}

static int _getIDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JNumValList    *pIDPList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getIssuingDistPointValue( pBinExt, &pIDPList );

    pCurList = pIDPList;

    while( pCurList )
    {
        QString strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

        if( bShow )
        {
            strVal += QString("[%1] Issuing Distribution Point:\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }

        pCurList = pCurList->pNext;
    }

    if( pIDPList ) JS_UTIL_resetNumValList( &pIDPList );
    return 0;
}

static int _getAltName( const BIN *pBinExt, int nNid, bool bShow, QString& strVal )
{
    int     ret = 0;
    JNumValList    *pAltNameList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getAlternativNameValue( pBinExt, &pAltNameList );

    pCurList = pAltNameList;

    while( pCurList )
    {
        QString strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

        if( bShow )
        {
            if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_OTHERNAME )
                strVal += QString( "%1: %2\n").arg( strType ).arg( pCurList->sNumVal.pValue );
            else
                strVal += QString( "%1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2").arg( strType ).arg(pCurList->sNumVal.pValue);
        }

        pCurList = pCurList->pNext;
    }

    if( pAltNameList ) JS_UTIL_resetNumValList( &pAltNameList );
    return 0;
}

static int _getPM( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JExtPolicyMappingsList *pPMList = NULL;
    JExtPolicyMappingsList *pCurList = NULL;

    ret = JS_PKI_getPolicyMappingsValue( pBinExt, &pPMList );

    pCurList = pPMList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Issuer Domain=%2\n" ).arg(i).arg(pCurList->sPolicyMappings.pIssuerDomainPolicy );
            if( pCurList->sPolicyMappings.pSubjectDomainPolicy )
                strVal += QString( " Subject Domain=%1\n" ).arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "IDP$%1#SDP$%2")
                .arg( pCurList->sPolicyMappings.pIssuerDomainPolicy )
                .arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pPMList ) JS_PKI_resetExtPolicyMappingsList( &pPMList );
    return 0;
}


static int _getNC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     pi = 1;
    int     ei = 1;

    JExtNameConstsList     *pNCList = NULL;
    JExtNameConstsList     *pCurList = NULL;

    ret = JS_PKI_getNameConstraintsValue( pBinExt, &pNCList );

    pCurList = pNCList;

    while( pCurList )
    {
        QString strType = JS_PKI_getGenNameString( pCurList->sNameConsts.nType );

        if( bShow )
        {
            if( pCurList->sNameConsts.nKind == JS_PKI_NAME_CONSTS_KIND_PST )
            {
                if( pi == 1 ) strVal += QString( "Permitted\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( pi ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                pi++;
            }
            else
            {
                if( ei == 1 ) strVal += QString( "Excluded\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( ei ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                ei++;
            }
        }
        else
        {
            strVal += QString("#%1$%2$%3$%4$%5")
                .arg( pCurList->sNameConsts.nKind )
                .arg( pCurList->sNameConsts.nType )
                .arg(pCurList->sNameConsts.pValue )
                .arg(pCurList->sNameConsts.nMin )
                .arg(pCurList->sNameConsts.nMax );
        }

        pCurList = pCurList->pNext;
    }

    return 0;
}

static int _getCRLReason( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nReason = -1;

    ret = JS_PKI_getCRLReasonValue( pBinExt, &nReason );

    if( nReason >= 0 ) strVal = crl_reasons[nReason];

    return 0;
}

const QString getExtValue( const QString strName, const QString strHexValue, bool bShow )
{
    int ret = 0;
    QString strVal;

    BIN     binExt = {0,0};

    JS_BIN_decodeHex( strHexValue.toStdString().c_str(), &binExt );

    if( strName == kExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, bShow, strVal );
    }
    else if( strName == kExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameSKI )
    {
        ret = _getSKI( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameAKI )
    {
        ret = _getAKI( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameEKU )
    {
        ret = _getEKU( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameBC )
    {
        ret = _getBC( &binExt, bShow, strVal );
    }
    else if( strName == kExtNamePC )
    {
        ret = _getPC( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameAIA )
    {
        ret = _getAIA( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameIDP )
    {
        ret = _getIDP( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameSAN || strName == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strName.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, bShow, strVal );
    }
    else if( strName == kExtNamePM )
    {
        ret = _getPM( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameNC )
    {
        ret = _getNC( &binExt, bShow, strVal );
    }
    else if( strName == kExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, bShow, strVal );
    }
    else
    {
        strVal = strHexValue;
    }

    JS_BIN_reset( &binExt );
    return strVal;
}

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal, bool bShow )
{
    int ret = 0;
    QString strSN = pExtInfo->pOID;
    BIN     binExt = {0,0};

    JS_BIN_decodeHex( pExtInfo->pValue, &binExt );

    if( strSN == kExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = _getSKI( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameAKI )
    {
        ret = _getAKI( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameEKU )
    {
        ret = _getEKU( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameBC )
    {
        ret = _getBC( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNamePC )
    {
        ret = _getPC( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameAIA )
    {
        ret = _getAIA( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameIDP )
    {
        ret = _getIDP( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameSAN || strSN == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, bShow, strVal );
    }
    else if( strSN == kExtNamePM )
    {
        ret = _getPM( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameNC )
    {
        ret = _getNC( &binExt, bShow, strVal );
    }
    else if( strSN == kExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, bShow, strVal );
    }
    else
    {
        strVal = pExtInfo->pValue;
    }

    JS_BIN_reset( &binExt );
}

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    getBINFromString( pBin, nType, strString );
}

void getBINFromString( BIN *pBin, int nType, const QString& strString )
{
    QString srcString = strString;

    if( pBin == NULL ) return;

    if( nType == DATA_HEX )
    {
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        JS_BIN_decodeHex( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_BASE64 )
    {
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        JS_BIN_decodeBase64( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
//        srcString.remove( QRegExp("[\t\r\n\\s]") );
        JS_UTIL_decodeURL( srcString.toStdString().c_str(), &pStr );

        if( pStr )
        {
            JS_BIN_set( pBin, (unsigned char *)pStr, strlen(pStr));
            JS_free( pStr );
        }
    }
    else
    {
        JS_BIN_set( pBin, (unsigned char *)srcString.toStdString().c_str(), srcString.length() );
    }
}

QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    return getStringFromBIN( pBin, nType, bSeenOnly );
}

static char _getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly )
{
    QString strOut;
    char *pOut = NULL;

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    if( nType == DATA_HEX )
    {
        JS_BIN_encodeHex( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_BASE64 )
    {
        JS_BIN_encodeBase64( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        JS_BIN_string( pBin, &pStr );
        JS_UTIL_encodeURL( pStr, &pOut );
        strOut = pOut;
        if( pStr ) JS_free( pStr );
    }
    else
    {
        int i = 0;

        if( bSeenOnly )
        {
            if( pBin->nLen > 0 )
            {
                pOut = (char *)JS_malloc(pBin->nLen + 1);

                for( i=0; i < pBin->nLen; i++ )
                    pOut[i] = _getch( pBin->pVal[i] );

                pOut[i] = 0x00;
            }
        }
        else
        {
            JS_BIN_string( pBin, &pOut );
        }

        strOut = pOut;
    }

    if( pOut ) JS_free( pOut );
    return strOut;
}

QString getKeyTypeName( int nKeyType )
{
    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        return "RSA";
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
        return "ECC";
    else if( nKeyType == JS_PKI_KEY_TYPE_SM2 )
        return "SM2";
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
        return "DSA";
    else if( nKeyType == JS_PKI_KEY_TYPE_ED25519 )
        return "Ed25519";
    else if( nKeyType == JS_PKI_KEY_TYPE_ED448 )
        return "Ed448";
    else if( nKeyType == JS_PKI_KEY_TYPE_AES )
        return "AES";
    else if( nKeyType == JS_PKI_KEY_TYPE_ARIA )
        return "ARIA";


    return QString( "Unknown[%1]").arg( nKeyType );
}

bool isEmail( const QString strEmail )
{
    QRegExp mailREX("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b");
    mailREX.setCaseSensitivity(Qt::CaseInsensitive );

    return mailREX.exactMatch( strEmail );
}

bool isValidNumFormat( const QString strInput, int nNumber )
{
    QRegExp strReg;

    if( nNumber == 2 )
    {
        strReg.setPattern( "[0-1]+");
    }
    else if( nNumber == 16 )
    {
        strReg.setPattern( "[0-9a-fA-F]+" );
    }
    else
    {
        strReg.setPattern( "[0-9]+" );
    }

    return strReg.exactMatch( strInput );
}

int getDataFromURI( const QString strURI, BIN *pData )
{
    int ret = 0;
    int nStatus = 0;

    QUrl url;
    QString strHost;
    int nPort = -1;
    url.setUrl( strURI );

    QString strScheme = url.scheme().toLower();

    if( strScheme == "http" || strScheme == "https" )
    {
        strHost = url.host();
        nPort = url.port(80);

        ret = JS_HTTP_requestGetBin2( strURI.toStdString().c_str(), NULL, NULL, &nStatus, pData );
    }
    else if( strScheme == "ldap" )
    {
        strHost = url.host();
        nPort = url.port( 389 );

        ret = JS_LDAP_getDataFromURI( strURI.toStdString().c_str(), pData );
    }
    else
    {
        ret = JS_BIN_fileReadBER( url.path().toLocal8Bit().toStdString().c_str(), pData );
        if( ret > 0 )
            ret = 0;
        else
            ret  -1;
    }

    return ret;
}

int checkOCSP( const QString strURL, const BIN *pCA, const BIN *pCert, JCertStatusInfo* pStatusInfo )
{
    int ret = 0;
    int nStatus = 0;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    JCertIDInfo sIDInfo;
    memset( &sIDInfo, 0x00, sizeof(sIDInfo));

    ret = JS_OCSP_encodeRequest( (BIN *)pCert, (BIN *)pCA, "SHA256", NULL, NULL, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode OCSP request: %d\n", ret );
        goto end;
    }

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/ocsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to request : %d\n", ret );
        goto end;
    }

    ret = JS_OCSP_decodeResponse( &binRsp, NULL, &sIDInfo, pStatusInfo );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode respose:%d\n", ret);
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    JS_OCSP_resetCertIDInfo( &sIDInfo );
//    JS_OCSP_resetCertStatusInfo( &sStatusInfo );

    return ret;
}
