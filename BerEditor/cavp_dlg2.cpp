#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>

#include "cavp_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"

static const int kACVP_TYPE_BLOCK_CIPHER = 0;
static const int kACVP_TYPE_HASH = 1;
static const int kACVP_TYPE_MAC = 2;
static const int kACVP_TYPE_RSA = 3;
static const int kACVP_TYPE_ECDSA = 4;
static const int kACVP_TYPE_DRBG = 5;
static const int kACVP_TYPE_KDA = 6;
static const int kACVP_TYPE_EDDSA = 7;
static const int kACVP_TYPE_DSA = 8;

static QStringList kACVP_HashList =
    { "SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512" };
static QStringList kACVP_BlockCipherList =
    { "ACVP-AES-ECB", "ACVP-AES-CBC", "ACVP-AES-CFB128", "ACVP-AES-OFB", "ACVP-AES-CTR", "ACVP-AES-CCM", "ACVP-AES-KW", "ACVP-AES-KWP", "ACVP-AES-GCM" };
static QStringList kACVP_MACList =
    { "HMAC-SHA-1", "HMAC-SHA2-224", "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512", "ACVP-AES-GMAC", "CMAC-AES" };
static QStringList kACVP_RSAList = { "RSA" };
static QStringList kACVP_ECDSAList = { "ECDSA" };
static QStringList kACVP_DRBGList = { "ctrDRBG", "hashDRBG", "hmacDRBG" };
static QStringList kACVP_KDAList = { "KAS-ECC", "kdf-components", "PBKDF" };
static QStringList kACVP_EDDSAList = { "EDDSA" };
static QStringList kACVP_DSAList = { "DSA" };

static int _getAlgMode( const QString strAlg, QString& strSymAlg, QString& strMode )
{
    QStringList strList = strAlg.split( "-" );

    if( strList.size() >= 3 )
    {
        strSymAlg = strList.at(1);
        strMode = strList.at(2);
    }
    else if( strList.size() == 2 )
    {
        strSymAlg = strList.at(0);
        strMode = strList.at(1);
    }
    else
    {
        return -1;
    }

    return 0;
}

static QString _getHashName( const QString strACVPHash )
{
    if( strACVPHash == "SHA-1" )
        return "SHA1";
    else if( strACVPHash == "SHA2-224" )
        return "SHA224";
    else if( strACVPHash == "SHA2-256" )
        return "SHA256";
    else if( strACVPHash == "SHA2-384" )
        return "SHA384";
    else if( strACVPHash == "SHA2-512" )
        return "SHA512";

    return "";
}

static QString _getHashNameFromMAC( const QString strACVPMac )
{
    if( strACVPMac == "HMAC-SHA-1" )
        return "SHA1";
    else if( strACVPMac == "HMAC-SHA2-224" )
        return "SHA224";
    else if( strACVPMac == "HMAC-SHA2-256" )
        return "SHA256";
    else if( strACVPMac == "HMAC-SHA2-384" )
        return "SHA384";
    else if( strACVPMac == "HMAC-SHA2-512" )
        return "SHA512";

    return "";
}

static QString _getECCurveName( const QString strACVPCurve )
{
    if( strACVPCurve == "P-256" )
        return "prime256v1";
    else if( strACVPCurve == "P-384" )
        return "secp384r1";
    else if( strACVPCurve == "P-521" )
        return "secp521r1";

    return "";
}

static int _getEdDSAType( const QString strACVPCurve )
{
    if( strACVPCurve == "ED-25519" )
        return JS_PKI_KEY_TYPE_ED25519;
    else if( strACVPCurve == "ED-448" )
        return JS_PKI_KEY_TYPE_ED448;

    return -1;
}

static int getACVPType( const QString strAlg )
{
    for( int i = 0; i < kACVP_HashList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_HashList.at(i).toUpper() )
            return kACVP_TYPE_HASH;
    }

    for( int i = 0; i < kACVP_BlockCipherList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_BlockCipherList.at(i).toUpper() )
            return kACVP_TYPE_BLOCK_CIPHER;
    }

    for( int i = 0; i < kACVP_MACList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_MACList.at(i).toUpper() )
            return kACVP_TYPE_MAC;
    }

    for( int i = 0; i < kACVP_RSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_RSAList.at(i).toUpper() )
            return kACVP_TYPE_RSA;
    }

    for( int i = 0; i < kACVP_ECDSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_ECDSAList.at(i).toUpper() )
            return kACVP_TYPE_ECDSA;
    }

    for( int i = 0; i < kACVP_DRBGList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_DRBGList.at(i).toUpper() )
            return kACVP_TYPE_DRBG;
    }

    for( int i = 0; i < kACVP_KDAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_KDAList.at(i).toUpper() )
            return kACVP_TYPE_KDA;
    }

    for( int i = 0; i < kACVP_EDDSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_EDDSAList.at(i).toUpper() )
            return kACVP_TYPE_EDDSA;
    }

    for( int i = 0; i < kACVP_DSAList.size(); i++ )
    {
        if( strAlg.toUpper() == kACVP_DSAList.at(i).toUpper() )
            return kACVP_TYPE_DSA;
    }

    return -1;
}

void CAVPDlg::clickACVPClear()
{
    mACVP_ReqPathText->clear();
}

void CAVPDlg::clickACVPRun()
{
    int ret = 0;

    QString strReqPath = mACVP_ReqPathText->text();
    QJsonDocument jReqDoc;

    QJsonDocument jRspDoc;
    QJsonArray jRspArr;
    QJsonObject jRspObj;
    QJsonArray jRspTestGroupArr;

    if( mACVP_SetTGIDCheck->isChecked() == true )
    {
        if( mACVP_SetTGIDText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a tgId" ), this );
            mACVP_SetTGIDText->setFocus();
            return;
        }
    }

    if( mACVP_SetTCIDCheck->isChecked() == true )
    {
        if( mACVP_SetTCIDText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a tcId" ), this );
            mACVP_SetTCIDText->setFocus();
            return;
        }
    }

    ret = readJsonReq( strReqPath, jReqDoc );
    if( ret != 0 ) return;

    QJsonArray jArr = jReqDoc.array();

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();


        if( i == 0 )
        {
            jRspArr.insert( 0, jObj );
        }
        else if( i == 1 )
        {
            QString strAlg = jObj["algorithm"].toString();
            QString strRevision = jObj["revision"].toString();
            QString strMode = jObj["mode"].toString();
            int nVsId = jObj["vsId"].toInt();

            QJsonArray jTestGroupArr = jObj["testGroups"].toArray();

//            if( strAlg == "ECDSA" || strAlg == "RSA" ) strAlg = strMode;

            jRspObj["algorithm"] = strAlg;
            jRspObj["revision"] = strRevision;
            jRspObj["vsId"] = nVsId;
            if( strMode.length() > 0 ) jRspObj["mode"] = strMode;

            for( int k = 0; k < jTestGroupArr.size(); k++ )
            {
                QJsonValue jSubVal = jTestGroupArr.at(k);
                QJsonObject jSubObj = jSubVal.toObject();
                int nTgId = jSubObj["tgId"].toInt();
                QJsonObject jRspObject;

                if( mACVP_SetTGIDCheck->isChecked() == true )
                {
                    int nSetTgId = mACVP_SetTGIDText->text().toInt();
                    if( nSetTgId != nTgId ) continue;
                }

                ret = makeUnitJsonWork( strAlg, strMode, jSubObj, jRspObject );
                if( ret != 0 ) break;

                if( mACVP_SetTGIDCheck->isChecked() == true )
                    jRspTestGroupArr.insert( 0, jRspObject );
                else
                    jRspTestGroupArr.insert( k, jRspObject );
            }

            jRspObj["testGroups"] = jRspTestGroupArr;
            jRspArr.insert( 1, jRspObj );
        }
    }

    jRspDoc.setArray( jRspArr );
    saveJsonRsp( jRspDoc );
}

void CAVPDlg::clickACVP_LDTClear()
{
    mACVP_LDTContentText->clear();
    mACVP_LDTFullLengthText->clear();
    mACVP_LDT_MDText->clear();
    mACVP_LDTStatusText->clear();
    mACVP_LDTProgressBar->setValue(0);
}

void CAVPDlg::clickACVP_LDTRun()
{
    int ret = 0;
    void *pCTX = NULL;

    QString strHash = mACVP_LDTHashCombo->currentText();
    QString strFullLength = mACVP_LDTFullLengthText->text();


    if( strFullLength.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a full length" ), this );
        mACVP_LDTFullLengthText->setFocus();
        return;
    }

    QString strContent = mACVP_LDTContentText->text();
    if( strContent.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a content" ), this );
        mACVP_LDTContentText->setFocus();
        return;
    }

    mACVP_LDTProgressBar->setValue( 0 );
    mACVP_LDTStatusText->clear();

    BIN binContent = {0,0};
    BIN binMD = {0,0};

    qint64 nFullLength = strFullLength.toLongLong() / 8;
    qint64 nCurLength = 0;

    JS_BIN_decodeHex( strContent.toStdString().c_str(), &binContent );

    ret = JS_PKI_hashInit( &pCTX, strHash.toStdString().c_str() );
    if( ret != 0 ) goto end;

    while( nFullLength > nCurLength )
    {
        int nPercent = 0;

        ret = JS_PKI_hashUpdate( pCTX, &binContent );
        if( ret != 0 ) goto end;

        nCurLength += binContent.nLen;

        nPercent = ( nCurLength * 100 ) / nFullLength;

        berApplet->log( QString( "CurLength: %1" ).arg( nCurLength * 8));
        mACVP_LDTProgressBar->setValue( nPercent );
        mACVP_LDTStatusText->setText( QString( "%1").arg( nCurLength * 8));
    }

    ret = JS_PKI_hashFinal( pCTX, &binMD );
    if( ret == 0 )
    {
        mACVP_LDT_MDText->setText( getHexString( &binMD ));
    }

end :
    JS_BIN_reset( &binContent );
    JS_BIN_reset( &binMD );

    if( pCTX ) JS_PKI_hashFree( &pCTX );
}

void CAVPDlg::clickACVP_LDTThreadRun()
{
    QString strContent = mACVP_LDTContentText->text();
    QString strFullLength = mACVP_LDTFullLengthText->text();

    if( strFullLength.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a full length bits" ), this );
        mACVP_LDTFullLengthText->setFocus();
        return;
    }

    if( strContent.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a content" ), this );
        mACVP_LDTContentText->setFocus();
        return;
    }

    startLDTHash();
}

void CAVPDlg::clickACVP_LDTThreadStop()
{
    stopLDTHash();
}

void CAVPDlg::ACVP_LDTContentChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mACVP_LDTContentLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::ACVP_LDT_MDChanged( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mACVP_LDT_MDLenText->setText( QString("%1").arg(strLen));
}

void CAVPDlg::clickFindACVPReqPath()
{
    QString strPath = mACVP_ReqPathText->text();

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_JSON, strPath );
    if( strFile.length() > 0 )
    {
        mACVP_ReqPathText->setText( strFile );
    }
}

void CAVPDlg::checkACVPSetTgId()
{
    bool bVal = mACVP_SetTGIDCheck->isChecked();
    mACVP_SetTGIDText->setEnabled( bVal );
}

void CAVPDlg::checkACVPSetTcId()
{
    bool bVal = mACVP_SetTCIDCheck->isChecked();
    mACVP_SetTCIDText->setEnabled( bVal );
}

void CAVPDlg::saveJsonRsp( const QJsonDocument& pJsonDoc )
{
    QDir dir;
    QString strRspPath = mRspPathText->text();
    QString strReqPath = mACVP_ReqPathText->text();

    QFileInfo fileInfo( strReqPath );
    QString strBaseName = fileInfo.baseName();

    QString strSaveName;

    QDateTime date;
    date.setTime_t( time(NULL));

    if( strRspPath.length() > 0 ) strRspPath += "/";

    strRspPath += "acvp_rsp";

    if( dir.exists( strRspPath ) == false )
        dir.mkdir( strRspPath );


    strSaveName = QString( "%1/%2_%3.json" )
                      .arg( strRspPath )
                      .arg( strBaseName )
                      .arg( date.toString( "yyyy_MM_dd_HHmmss" ));

    QFile saveFile( strSaveName );
    saveFile.open(QFile::WriteOnly | QFile::Append| QFile::Text );
    saveFile.write( pJsonDoc.toJson() );
    saveFile.close();

    berApplet->messageBox( tr( "%1 file save successfully").arg( strSaveName ), this );

}

int CAVPDlg::readJsonReq( const QString strPath, QJsonDocument& pJsonDoc )
{
    QFile jsonFile( strPath );
    berApplet->log( QString( "Json Path: %1").arg( strPath ));

    if( !jsonFile.open( QIODevice::ReadOnly))
    {
        berApplet->elog( QString( "fail to read json: %1").arg( strPath));
        return -1;
    }

    QByteArray fileByte = jsonFile.readAll();
    berApplet->log( QString("Json Size: %1").arg( fileByte.size() ));

    jsonFile.close();

    pJsonDoc = QJsonDocument::fromJson( fileByte );

    return 0;
}

int CAVPDlg::makeUnitJsonWork( const QString strAlg, const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    int nACVP_Type = -1;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    if( isSkipTestType( strTestType ) == true )
    {
        QJsonObject jSkipObj;
        jRspObject["tests"] = jSkipObj;
        jRspObject["tgId"] = nTgId;

        return 0;
    }

    nACVP_Type = getACVPType( strAlg );

    switch ( nACVP_Type ) {
    case kACVP_TYPE_BLOCK_CIPHER :
        ret = blockCipherJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_HASH :
        ret = hashJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_MAC :
        ret = macJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_RSA :
        ret = rsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_ECDSA :
        ret = ecdsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_DRBG :
        ret = drbgJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_KDA :
        ret = kdaJsonWork( strAlg, jObject, jRspObject );
        break;

    case kACVP_TYPE_EDDSA:
        ret = eddsaJsonWork( strMode, jObject, jRspObject );
        break;

    case kACVP_TYPE_DSA:
        ret = dsaJsonWork( strMode, jObject, jRspObject );
        break;

    default:
        ret = -1;
        berApplet->warnLog( QString( "Invalid Algorithm: %1" ).arg( strAlg ), this );
        break;
    }

    return ret;
}

int CAVPDlg::hashJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strMctVersion = jObject["mctVersion"].toString();

    int nTgId = jObject["tgId"].toInt();
    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binMsg = {0,0};
    BIN binMD = {0,0};

    QString strHash = _getHashName( strAlg );

    if( strHash.length() < 1 )
    {
        berApplet->warningBox( QString("Invalid algorithm: %1").arg( strAlg ), this );
        return -1;
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["msg"].toString();

        QJsonObject jRspTestObj;

        jRspTestObj["tcId"] = nTcId;

        JS_BIN_reset( &binMD );
        JS_BIN_reset( &binMsg );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "LDT" )
        {
            void *pCTX = NULL;
            QJsonObject jLDTObj = jObj["largeMsg"].toObject();
            QString strContent = jLDTObj["content"].toString();
            int nContentLength = jLDTObj["contentLength"].toInt();
            QString strExpansionTechnique = jLDTObj["repeating"].toString();
            qint64 nFullLength = jLDTObj["fullLength"].toDouble();

            qint64 nFullBytes = nFullLength / 8;
            qint64 nLeft = nFullBytes;

            BIN binData = {0,0};
            BIN binMD = {0,0};

            JS_BIN_decodeHex( strContent.toStdString().c_str(), &binData );

            ret = JS_PKI_hashInit( &pCTX, strHash.toStdString().c_str() );

            if( ret != 0 )
            {
                JS_BIN_reset( &binData );
                goto end;
            }

            while( nLeft > 0 )
            {
                ret = JS_PKI_hashUpdate( pCTX, &binData );
                if( ret != 0 )
                {
                    JS_BIN_reset( &binData );
                    goto end;
                }

                nLeft -= binData.nLen;
            }

            ret = JS_PKI_hashFinal( pCTX, &binMD );

            if( ret == 0 ) jRspObject["md"] = getHexString( &binMD );

            JS_BIN_reset( &binMD );
            JS_BIN_reset( &binData );
        }
        else if( strTestType == "MCT" )
        {
            QJsonArray jMDArr;

            if( strMctVersion == "alternate" )
                ret = makeHashAlternateMCT( strAlg.toStdString().c_str(), strMsg, &jMDArr );
            else
                ret = makeHashMCT( strAlg.toStdString().c_str(), strMsg, &jMDArr );

            if( ret != 0 ) goto end;

            jRspTestObj["resultsArray"] = jMDArr;
        }
        else
        {
            ret = JS_PKI_genHash( strHash.toStdString().c_str(), &binMsg, &binMD );
            if( ret != 0 ) goto end;

            jRspTestObj["md"] = getHexString( &binMD );
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binMD );

    return ret;
}

int CAVPDlg::ecdsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    QString strCurve = jObject["curve"].toString();
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strConformance = jObject["conformance"].toString();
    QString strSecretGerenationMode = jObject["secretGenerationMode"].toString();

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binMsg = {0,0};
    BIN binSign = {0,0};

    BIN binR = {0,0};
    BIN binS = {0,0};

    BIN binQX = {0,0};
    BIN binQY = {0,0};

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strUseHash = _getHashName( strHashAlg );
    QString strUseCurve = _getECCurveName( strCurve );

    if( strMode == "sigGen" )
    {
        JECKeyVal sECKeyVal;

        memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

        ret = JS_PKI_ECCGenKeyPair( strUseCurve.toStdString().c_str(), &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
        if( ret != 0 ) goto end;

        jRspObject["qx"] = sECKeyVal.pPubX;
        jRspObject["qy"] = sECKeyVal.pPubY;

        JS_PKI_resetECKeyVal( &sECKeyVal );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["message"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strQX = jObj["qx"].toString();
        QString strQY = jObj["qy"].toString();

        QString strR = jObj["r"].toString();
        QString strS = jObj["s"].toString();

        JS_BIN_reset( &binSign );
        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
        JS_BIN_reset( &binQX );
        JS_BIN_reset( &binQY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strMode == "keyGen" )
            {
                JECKeyVal sECKeyVal;

                memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

                JS_BIN_reset( &binPub );
                JS_BIN_reset( &binPri );

                ret = JS_PKI_ECCGenKeyPair( strUseCurve.toStdString().c_str(), &binPub, &binPri );
                if( ret != 0 ) goto end;

                ret = JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
                if( ret != 0 ) goto end;

                jRspTestObj["d"] = sECKeyVal.pPrivate;
                jRspTestObj["qx"] = sECKeyVal.pPubX;
                jRspTestObj["qy"] = sECKeyVal.pPubY;

                JS_PKI_resetECKeyVal( &sECKeyVal );
            }
            else if( strMode == "keyVer" )
            {
                bool bRes = false;

                JS_BIN_decodeHex( strQX.toStdString().c_str(), &binQX );
                JS_BIN_decodeHex( strQY.toStdString().c_str(), &binQY );

                ret = JS_PKI_IsValidECCPubKey( strUseCurve.toStdString().c_str(), &binQX, &binQY );
                if( ret == JSR_VALID )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
            }
            else if( strMode == "sigGen" )
            {
                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

                ret = JS_PKI_ECCMakeSign( strUseHash.toStdString().c_str(), &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_decodeECCSign( &binSign, &binR, &binS );
                if( ret != 0 ) goto end;

                jRspTestObj["r"] = getHexString( &binR );
                jRspTestObj["s"] = getHexString( &binS );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
                if( strR.length() > 0 ) JS_BIN_decodeHex( strR.toStdString().c_str(), &binR );
                if( strS.length() > 0 ) JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );

                JECKeyVal sECKeyVal;

                char sOID[1024];

                memset( sOID, 0x00, sizeof(sOID));

                memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));
                JS_PKI_getOIDFromSN( strUseCurve.toStdString().c_str(), sOID );

                sECKeyVal.pCurveOID = sOID;
                sECKeyVal.pPubX = (char *)strQX.toStdString().c_str();
                sECKeyVal.pPubY = (char *)strQY.toStdString().c_str();
                JS_BIN_reset( &binPub );

                ret = JS_PKI_encodeECPublicKey( &sECKeyVal, &binPub );
                if( ret != 0 ) goto end;

                // Need to make sign
                ret = JS_PKI_encodeECCSign( &binR, &binS, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_ECCVerifySign( strUseHash.toStdString().c_str(), &binMsg, &binSign, &binPub );
                if( ret == JSR_VERIFY )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;
                ret = 0;
            }
            else
            {
                berApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binQX );
    JS_BIN_reset( &binQY );

    return ret;
}

int CAVPDlg::eddsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    QString strCurve = jObject["curve"].toString();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    int nEdDSA_Type = _getEdDSAType( strCurve );

    bool bPreHash = jObject["preHash"].toBool();

    BIN binMsg = {0,0};
    BIN binSign = {0,0};
    BIN binD = {0,0};
    BIN binQ = {0,0};

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    if( strMode == "sigGen" )
    {
        ret = JS_PKI_EdDSA_GenKeyPair( nEdDSA_Type, &binPub, &binPri );
        if( ret != 0 ) goto end;

        jRspObject["q"] = getHexString( &binPub );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["message"].toString();
        QString strSign = jObj["signature"].toString();
        QString strQ = jObj["q"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binSign );
        JS_BIN_reset( &binD );
        JS_BIN_reset( &binQ );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
        if( strSign.length() > 0 ) JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );
        if( strQ.length() > 0 ) JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" || strTestType == "BFT" )
        {
            if( strMode == "keyGen" )
            {
                ret = JS_PKI_EdDSA_GenKeyPair( nEdDSA_Type, &binQ, &binD );
                if( ret != 0 ) goto end;

                jRspTestObj["d"] = getHexString( &binD );
                jRspTestObj["q"] = getHexString( &binQ );
            }
            else if( strMode == "keyVer" )
            {
#if 1
                berApplet->elog( QString( "(%1) does not support" ).arg( strMode ));
                ret = -1;
                goto end;
#else
                bool bRes = false;
                ret = JS_PKI_encodeRawPublicKeyValue( nEdDSA_Type, &binQ, &binPub );
                if( ret != 0 ) goto end;

                ret = JS_PKI_checkPublicKey( &binPub );

                if( ret == JSR_VALID )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
#endif
            }
            else if( strMode == "sigGen" )
            {
                ret = JS_PKI_EdDSA_Sign( nEdDSA_Type, &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                jRspTestObj["signature"] = getHexString( &binSign );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;

                ret = JS_PKI_encodeRawPublicKeyValue( nEdDSA_Type, &binQ, &binPub );
                if( ret != 0 ) goto end;

                ret = JS_PKI_EdDSA_Verify( &binMsg, &binSign, &binPub );
                if( ret == JSR_VERIFY )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
            }
            else
            {
                berApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binD );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );

    return ret;
}

int CAVPDlg::rsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    int nModulo = jObject["modulo"].toInt();

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binSign = {0,0};
    BIN binMsg = {0,0};
    BIN binE = {0,0};

    //KeyGen
    bool bInfoGeneratedByServer = jObject["infoGeneratedByServer"].toBool();
    QString strKeyFormat = jObject["keyFormat"].toString();

    QString strPrimeTest = jObject["primeTest"].toString();
    QString strPubExp = jObject["pubExp"].toString();
    QString strRandPQ = jObject["randPQ"].toString();
    QString strFixedPubExp = jObject["fixedPubExp"].toString();

    //SigGen or SigVer
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strMaskFunction = jObject["maskFunction"].toString();
    int nSaltLen = jObject["saltLen"].toInt();
    QString strSigType = jObject["sigType"].toString();

    QString strE = jObject["e"].toString();
    QString strN = jObject["n"].toString();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strUseHash = _getHashName( strHashAlg );

    if( strMode == "sigGen" )
    {
        int nExponent = 65537;
        JRSAKeyVal sRSAKeyVal;

        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        ret = JS_PKI_RSAGenKeyPair( nModulo, nExponent, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKeyVal );
        if( ret != 0 ) goto end;

        jRspObject["e"] = sRSAKeyVal.pE;
        jRspObject["n"] = sRSAKeyVal.pN;

        JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
    }
    else if( strMode == "sigVer" )
    {
        JRSAKeyVal sRSAKeyVal;

        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        sRSAKeyVal.pE = (char *)strE.toStdString().c_str();
        sRSAKeyVal.pN = (char *)strN.toStdString().c_str();

        ret = JS_PKI_encodeRSAPublicKey( &sRSAKeyVal, &binPub );
        if( ret != 0 ) goto end;
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        bool bDeferred = jObj["deferred"].toBool();
        QString strMsg = jObj["message"].toString();
        QString strSign = jObj["signature"].toString();
        QString strValE = jObj["e"].toString();
        QString strValP = jObj["p"].toString();
        QString strValQ = jObj["q"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "GDT" )
        {
            if( strMode == "keyGen" )
            {
                int nExponent = 0;
                JRSAKeyVal sRSAKey;

                JS_BIN_reset( &binPri );
                JS_BIN_reset( &binPub );

                JS_BIN_reset( &binE );
                JS_BIN_decodeHex( strFixedPubExp.toStdString().c_str(), &binE );

                nExponent = JS_BIN_int( &binE );

                memset( &sRSAKey, 0x00, sizeof(sRSAKey));

                ret = JS_PKI_RSAGenKeyPair( nModulo, nExponent, &binPub, &binPri );
                if( ret != 0 ) goto end;

                ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKey );
                if( ret != 0 ) goto end;

                jRspTestObj["d"] = sRSAKey.pD;
                jRspTestObj["e"] = sRSAKey.pE;
                jRspTestObj["n"] = sRSAKey.pN;
                jRspTestObj["p"] = sRSAKey.pP;
                jRspTestObj["q"] = sRSAKey.pQ;

                JS_PKI_resetRSAKeyVal( &sRSAKey );
            }
            else if( strMode == "sigGen" )
            {
                int nVersion = JS_PKI_RSA_PADDING_V15;

                if( strSigType == "pss" )
                    nVersion = JS_PKI_RSA_PADDING_V21;

                JS_BIN_reset( &binMsg );
                JS_BIN_reset( &binSign );

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

                ret = JS_PKI_RSAMakeSign( strUseHash.toStdString().c_str(), nVersion, &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                jRspTestObj["signature"] = getHexString( &binSign );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;

                int nVersion = JS_PKI_RSA_PADDING_V15;

                if( strSigType == "pss" )
                    nVersion = JS_PKI_RSA_PADDING_V21;

                JS_BIN_reset( &binMsg );
                JS_BIN_reset( &binSign );

                if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
                if( strSign.length() > 0 ) JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

                ret = JS_PKI_RSAVerifySign( strUseHash.toStdString().c_str(), nVersion, &binMsg, &binSign, &binPub );
                if( ret == JSR_VERIFY ) bRes = true;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
            }
            else
            {
                berApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binE );

    return ret;
}

int CAVPDlg::dsaJsonWork( const QString strMode, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    int nL = jObject["l"].toInt();
    int nN = jObject["n"].toInt();
    QString strHashAlg = jObject["hashAlg"].toString();
    QString strG = jObject["g"].toString();
    QString strP = jObject["p"].toString();
    QString strQ = jObject["q"].toString();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binG = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};

    BIN binMsg = {0,0};
    BIN binSign = {0,0};
    BIN binR = {0,0};
    BIN binS = {0,0};
    BIN binY = {0,0};

    BIN binParam = {0,0};
    BIN binPub = {0,0};
    BIN binPri = {0,0};

    QString strUseHash = _getHashName( strHashAlg );

    if( strMode == "keyGen" || strMode == "sigGen" )
    {
        ret = JS_PKI_DSA_GenParam( nL, &binParam );
        if( ret != 0 ) goto end;

        ret = JS_PKI_DSA_GetParamValue( &binParam, &binP, &binQ, &binG );
        if( ret != 0 ) goto end;

        jRspObject["g"] = getHexString( &binG );
        jRspObject["p"] = getHexString( &binP );
        jRspObject["q"] = getHexString( &binQ );

        if( strMode == "sigGen" )
        {
            JDSAKeyVal sDSAKey;

            memset( &sDSAKey, 0x00, sizeof(sDSAKey));

            ret = JS_PKI_DSA_GenKeyPairWithParam( &binParam, &binPub, &binPri );
            if( ret != 0 ) goto end;

            ret = JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
            if( ret != 0 ) goto end;

            jRspObject["y"] = sDSAKey.pPublic;

            JS_PKI_resetDSAKeyVal( &sDSAKey );
        }
    }
    else if( strMode == "sigVer" )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strMsg = jObj["message"].toString();
        QString strR = jObj["r"].toString();
        QString strS = jObj["s"].toString();
        QString strY = jObj["y"].toString();

        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
        JS_BIN_reset( &binY );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
        if( strR.length() > 0 ) JS_BIN_decodeHex( strR.toStdString().c_str(), &binR );
        if( strS.length() > 0 ) JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );
        if( strY.length() > 0 ) JS_BIN_decodeHex( strY.toStdString().c_str(), &binY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strMode == "keyGen" )
            {
                JDSAKeyVal sDSAKey;

                JS_BIN_reset( &binPub );
                JS_BIN_reset( &binPri );

                memset( &sDSAKey, 0x00, sizeof(sDSAKey));

                ret = JS_PKI_DSA_GenKeyPairWithParam( &binParam, &binPub, &binPri );
                if( ret != 0 ) goto end;

                ret = JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
                if( ret != 0 ) goto end;

                jRspTestObj["x"] = sDSAKey.pPrivate;
                jRspTestObj["y"] = sDSAKey.pPublic;

                JS_PKI_resetDSAKeyVal( &sDSAKey );
            }
            else if( strMode == "sigGen" )
            {
                JS_BIN_reset( &binSign );
                JS_BIN_reset( &binR );
                JS_BIN_reset( &binS );

                ret = JS_PKI_DSA_Sign( strUseHash.toStdString().c_str(), &binMsg, &binPri, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_decodeSign( &binSign, &binR, &binS );
                if( ret != 0 ) goto end;

                jRspTestObj["r"] = getHexString( &binR );
                jRspTestObj["s"] = getHexString( &binS );
            }
            else if( strMode == "sigVer" )
            {
                bool bRes = false;
                JDSAKeyVal sDSAKey;

                memset( &sDSAKey, 0x00, sizeof(sDSAKey));

                JS_BIN_reset( &binSign );
                JS_BIN_reset( &binPub );

                sDSAKey.pG = (char *)strG.toStdString().c_str();
                sDSAKey.pP = (char *)strP.toStdString().c_str();
                sDSAKey.pQ = (char *)strQ.toStdString().c_str();
                sDSAKey.pPublic = (char *)strY.toStdString().c_str();

                ret = JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_encodeSign( &binR, &binS, &binSign );
                if( ret != 0 ) goto end;

                ret = JS_PKI_DSA_Verify( strUseHash.toStdString().c_str(), &binMsg, &binSign, &binPub );
                if( ret == JSR_VERIFY )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;

                ret = 0;
            }
            else
            {
                berApplet->warnLog( tr("Invalid Mode: %1").arg( strMode ), this );
                ret = -1;
                goto end;
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binY );

    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );

    return ret;
}

int CAVPDlg::macJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strDirection = jObject["direction"].toString();
    int nTgId = jObject["tgId"].toInt();
    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    QString strSymAlg;
    QString strMode;

    if( _getAlgMode( strAlg, strSymAlg, strMode ) != 0 )
        return -1;

    BIN binMsg = {0,0};
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binAAD = {0,0};
    BIN binMAC = {0,0};
    BIN binTag = {0,0};

    int nAadLen = jObject["aadLen"].toInt();
    QString strIvGen = jObject["ivGen"].toString();
    int nPayloadLen = jObject["payloadLen"].toInt();
    int nIVLen = jObject["ivLen"].toInt();
    int nTagLen = jObject["tagLen"].toInt();

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QString strMsg;
        QString strKey = jObj["key"].toString();
        QString strMAC = jObj["mac"].toString();

        QString strAad = jObj["aad"].toString();
        QString strIv = jObj["iv"].toString();
        QString strTag = jObj["tag"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        if( strMode == "AES" && strSymAlg == "CMAC" )
            strMsg = jObj["message"].toString();
        else
            strMsg = jObj["msg"].toString();

        JS_BIN_reset( &binMsg );
        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binAAD );
        JS_BIN_reset( &binMAC );
        JS_BIN_reset( &binTag );

        if( strMsg.length() > 0 ) JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );
        if( strKey.length() > 0 ) JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
        if( strMAC.length() > 0 ) JS_BIN_decodeHex( strMAC.toStdString().c_str(), &binMAC );
        if( strAad.length() > 0 ) JS_BIN_decodeHex( strAad.toStdString().c_str(), &binAAD );
        if( strIv.length() > 0 ) JS_BIN_decodeHex( strIv.toStdString().c_str(), &binIV );
        if( strTag.length() > 0 ) JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strDirection == "decrypt" || strDirection == "ver" )
            {
                bool bRes = false;
                BIN binGenMAC = {0,0};

                if( strMode == "GMAC" )
                {
                    ret = JS_PKI_genGMAC( strSymAlg.toStdString().c_str(), &binAAD, &binKey, &binIV, &binGenMAC );
                    if( ret != 0 ) goto end;

                    JS_BIN_copy( &binMAC, &binTag );
                }
                else if( strMode == "AES" && strSymAlg == "CMAC" )
                {
                    QString strMACAlg = getSymAlg( strMode, "CBC", binKey.nLen );
                    ret = JS_PKI_genCMAC( strMACAlg.toStdString().c_str(), &binMsg, &binKey, &binGenMAC );
                    if( ret != 0 ) goto end;
                }
                else
                {
                    QString strUseHash = _getHashNameFromMAC( strAlg );
                    ret = JS_PKI_genHMAC( strUseHash.toStdString().c_str(), &binMsg, &binKey, &binGenMAC );
                    if( ret != 0 ) goto end;
                }

                if( JS_BIN_cmp( &binGenMAC, &binMAC ) == 0 )
                    bRes = true;
                else
                    bRes = false;

                jRspTestObj["testPassed"] = bRes;
            }
            else
            {
                if( strMode == "GMAC" )
                {
                    ret = JS_PKI_genGMAC( strSymAlg.toStdString().c_str(), &binAAD, &binKey, &binIV, &binMAC );
                    if( ret != 0 ) goto end;

                    jRspTestObj["tag"] = getHexString( &binMAC );
                }
                else if( strMode == "AES" && strSymAlg == "CMAC" )
                {
                    QString strMACAlg = getSymAlg( strMode, "CBC", binKey.nLen );
                    ret = JS_PKI_genCMAC( strMACAlg.toStdString().c_str(), &binMsg, &binKey, &binMAC );
                    if( ret != 0 ) goto end;
                    jRspTestObj["mac"] = getHexString( &binMAC );
                }
                else
                {
                    QString strUseHash = _getHashNameFromMAC( strAlg );
                    ret = JS_PKI_genHMAC( strUseHash.toStdString().c_str(), &binMsg, &binKey, &binMAC );
                    if( ret != 0 ) goto end;

                    jRspTestObj["mac"] = getHexString( &binMAC );
                }
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binMAC );
    JS_BIN_reset( &binTag );

    return ret;
}



int CAVPDlg::blockCipherJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    QString strDirection = jObject["direction"].toString();
    int nTgId = jObject["tgId"].toInt();
    int nKeyLen = jObject["keyLen"].toInt();

    QString strSymAlg;
    QString strMode;

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    if( _getAlgMode( strAlg, strSymAlg, strMode ) != 0 )
        return -1;

    int nAADLen = jObject["aadLen"].toInt();
    QString strIVGen = jObject["ivGen"].toString();
    int nIVLen = jObject["ivLen"].toInt();
    int nPayLoadLen = jObject["payloadLen"].toInt();
    int nTagLen = jObject["tagLen"].toInt();

    QString strKwCipher = jObject["kwCipher"].toString();

    BIN binKey = {0,0};
    BIN binCT = {0,0};
    BIN binPT = {0,0};
    BIN binIV = {0,0};
    BIN binTag = {0,0};
    BIN binAAD = {0,0};

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["msg"].toString();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strPT = jObj["pt"].toString();
        QString strCT = jObj["ct"].toString();
        QString strIV = jObj["iv"].toString();
        QString strKey = jObj["key"].toString();

        QString strAAD = jObj["aad"].toString();
        QString strTag = jObj["tag"].toString();

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binCT );
        JS_BIN_reset( &binPT );
        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binTag );
        JS_BIN_reset( &binAAD );

        if( strPT.length() > 0 ) JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT );
        if( strCT.length() > 0 ) JS_BIN_decodeHex( strCT.toStdString().c_str(), &binCT );
        if( strIV.length() > 0 ) JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
        if( strKey.length() > 0 ) JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
        if( strAAD.length() > 0 ) JS_BIN_decodeHex( strAAD.toStdString().c_str(), &binAAD );
        if( strTag.length() > 0 ) JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "MCT" )
        {
            QJsonArray jSymArr;

            if( strMode == "CCM" || strMode == "GCM" )
                return -2;

            if( strMode == "CFB128" ) strMode = "CFB";

            if( strDirection == "encrypt" )
            {
                if( strMode == "ECB" )
                    ret = makeSymECB_MCT( strSymAlg, strKey, strPT, &jSymArr );
                else if( strMode == "CBC" )
                    ret = makeSymCBC_MCT( strSymAlg, strKey, strIV, strPT, &jSymArr );
                else if( strMode == "CTR" )
                    ret = makeSymCTR_MCT( strSymAlg, strKey, strIV, strPT, &jSymArr );
                else if( strMode == "CFB" )
                    ret = makeSymCFB_MCT( strSymAlg, strKey, strIV, strPT, &jSymArr );
                else if( strMode == "OFB" )
                    ret = makeSymOFB_MCT( strSymAlg, strKey, strIV, strPT, &jSymArr );
            }
            else
            {
                if( strMode == "ECB" )
                    ret = makeSymDecECB_MCT( strSymAlg, strKey, strCT, &jSymArr );
                else if( strMode == "CBC" )
                    ret = makeSymDecCBC_MCT( strSymAlg, strKey, strIV, strCT, &jSymArr );
                else if( strMode == "CTR" )
                    ret = makeSymDecCTR_MCT( strSymAlg, strKey, strIV, strCT, &jSymArr );
                else if( strMode == "CFB" )
                    ret = makeSymDecCFB_MCT( strSymAlg, strKey, strIV, strCT, &jSymArr );
                else if( strMode == "OFB" )
                    ret = makeSymDecOFB_MCT( strSymAlg, strKey, strIV, strCT, &jSymArr );
            }

            if( ret != 0 ) goto end;

            jRspTestObj["resultsArray"] = jSymArr;
        }
        else if( strTestType == "CTR" )
        {
            int nLeft = 0;
            int nBlock = 16;
            int nPos = 0;
            BIN binPart = {0,0};
            BIN binRes = {0,0};

            QString strCipher = getSymAlg( strSymAlg, strMode, nKeyLen/8 );

            if( strMode.toUpper() != "CTR" )
                return -2;

            if( strDirection == "encrypt" )
            {
                nLeft = binPT.nLen;

                while( nLeft > 0 )
                {
                    if( nLeft < nBlock ) nBlock = nLeft;

                    binPart.nLen = nBlock;
                    binPart.pVal = &binPT.pVal[nPos];

                    ret = JS_PKI_encryptData( strCipher.toStdString().c_str(), 0, &binPart, &binIV, &binKey, &binRes );
                    if( ret != 0 ) return ret;

                    JS_BIN_appendBin( &binCT, &binRes );
                    JS_BIN_reset( &binRes );
                    JS_BIN_DEC( &binIV );

                    nLeft -= nBlock;
                    nPos += nBlock;
                }

                jRspTestObj["ct"] = getHexString( &binCT );
            }
            else
            {
                nLeft = binCT.nLen;

                while( nLeft > 0 )
                {
                    if( nLeft < nBlock ) nBlock = nLeft;

                    binPart.nLen = nBlock;
                    binPart.pVal = &binCT.pVal[nPos];

                    ret = JS_PKI_encryptData( strCipher.toStdString().c_str(), 0, &binPart, &binIV, &binKey, &binRes );
                    if( ret != 0 ) return ret;

                    JS_BIN_appendBin( &binPT, &binRes );
                    JS_BIN_reset( &binRes );
                    JS_BIN_DEC( &binIV );

                    nLeft -= nBlock;
                    nPos += nBlock;
                }

                jRspTestObj["pt"] = getHexString( &binPT );
            }
        }
        else // AFT
        {
            QString strCipher = getSymAlg( strSymAlg, strMode, nKeyLen/8 );

            if( strDirection == "encrypt" )
            {
                if( strMode.toUpper() == "GCM" || strMode.toUpper() == "CCM" )
                {
                    if( strMode == "CCM" )
                    {
                        ret = JS_PKI_encryptCCM( strCipher.toStdString().c_str(), &binPT, &binKey, &binIV, &binAAD, nTagLen/8, &binTag, &binCT );

                        JS_BIN_appendBin( &binCT, &binTag );
                        jRspTestObj["ct"] = getHexString( &binCT );
                    }
                    else
                    {
                        ret = JS_PKI_encryptGCM( strCipher.toStdString().c_str(), &binPT, &binKey, &binIV, &binAAD, nTagLen/8, &binTag, &binCT );

                        if( ret != 0 ) goto end;

                        jRspTestObj["tag"] = getHexString( &binTag );
                        jRspTestObj["ct"] = getHexString( &binCT );
                    }
                }
                else if( strMode.toUpper() == "KW" || strMode.toUpper() == "KWP" )
                {
                    int nPad = 0;
                    if( strMode == "KWP" ) nPad = 1;

                    if( strKwCipher == "inverse" )
                    {
                        berApplet->elog( QString( "KwCiper(%1) does not support" ).arg( strKwCipher ));
                        ret = -1;
                        goto end;
                    }

                    ret = JS_PKI_WrapKey( nPad, &binKey, &binPT, &binCT );
                    if( ret != 0 ) goto end;

                    jRspTestObj["ct"] = getHexString( &binCT );
                }
                else
                {
                    ret = JS_PKI_encryptData( strCipher.toStdString().c_str(), 0, &binPT, &binIV, &binKey, &binCT);
                    if( ret != 0 ) goto end;

                    jRspTestObj["ct"] = getHexString( &binCT );
                }


            }
            else
            {
                if( strMode.toUpper() == "GCM" || strMode.toUpper() == "CCM" )
                {
                    if( strMode == "CCM" )
                    {
                        int nTagBytes = nTagLen / 8;

                        JS_BIN_set( &binTag, &binCT.pVal[binCT.nLen-nTagBytes], nTagBytes );
                        binCT.nLen = binCT.nLen - nTagBytes;

                        ret = JS_PKI_decryptCCM( strCipher.toStdString().c_str(), &binCT, &binKey, &binIV, &binAAD, &binTag, &binPT );
                    }
                    else
                    {
                        ret = JS_PKI_decryptGCM( strCipher.toStdString().c_str(), &binCT, &binKey, &binIV, &binAAD, &binTag, &binPT );
                    }

                    if( ret == 0 )
                        jRspTestObj["pt"] = getHexString( &binPT );
                    else
                        jRspTestObj["testPassed"] = false;

                    ret = 0;
                }
                else if( strMode.toUpper() == "KW" || strMode.toUpper() == "KWP" )
                {
                    int nPad = 0;
                    if( strMode == "KWP" ) nPad = 1;

                    ret = JS_PKI_UnwrapKey( nPad, &binKey, &binCT, &binPT );

                    if( ret == 0 )
                        jRspTestObj["pt"] = getHexString( &binPT );
                    else
                        jRspTestObj["testPassed"] = false;

                    ret = 0;
                }
                else
                {
                    ret = JS_PKI_decryptData( strCipher.toStdString().c_str(), 0, &binCT, &binIV, &binKey, &binPT );
                    jRspTestObj["pt"] = getHexString( &binPT );

                    if( ret != 0 ) goto end;
                }


            }
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binCT );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binTag );
    JS_BIN_reset( &binAAD );

    return ret;
}

int CAVPDlg::kdaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    // For KAS-ECC
    QString strCurve = jObject["curve"].toString();
    QString strUseCurve = _getECCurveName( strCurve );

    // For kdf-components
    int nFieldSize = jObject["fieldSize"].toInt();
    QString strHashAlg = jObject["hashAlg"].toString();
    int nKeyDataLength = jObject["keyDataLength"].toInt();
    int nSharedInfoLength = jObject["sharedInfoLength"].toInt();

    QString strHmacAlg = jObject["hmacAlg"].toString();

    QString strUseHash;

    if( strHashAlg.length() > 0 )
        strUseHash = _getHashName( strHashAlg );
    else if( strHmacAlg.length() > 0 )
        strUseHash = _getHashName( strHmacAlg );

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binKey = {0,0};
    BIN binInfo = {0,0};
    BIN binSecret = {0,0};

    BIN binPubSrvX = {0,0};
    BIN binPubSrvY = {0,0};

    BIN binSalt = {0,0};
    BIN binDerivedKey = {0,0};

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        //kdf-components
        QString strSharedInfo = jObj["sharedInfo"].toString();
        QString strZ = jObj["z"].toString();

        // KAS-ECC
        QString strPublicServerX = jObj["publicServerX"].toString();
        QString strPublicServerY = jObj["publicServerY"].toString();

        // PBKDF
        int nKeyLen = jObj["keyLen"].toInt();
        int nIterCount = jObj["iterationCount"].toInt();
        QString strPassword = jObj["password"].toString(); // Base64 encoding
        QString strSalt = jObj["salt"].toString();

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binInfo );
        JS_BIN_reset( &binSecret );

        JS_BIN_reset( &binPubSrvX );
        JS_BIN_reset( &binPubSrvY );

        JS_BIN_reset( &binDerivedKey );
        JS_BIN_reset( &binSalt );

        if( strSharedInfo.length() > 0 ) JS_BIN_decodeHex( strSharedInfo.toStdString().c_str(), &binInfo );
        if( strZ.length() > 0 ) JS_BIN_decodeHex( strZ.toStdString().c_str(), &binSecret );

        if( strPublicServerX.length() > 0 ) JS_BIN_decodeHex( strPublicServerX.toStdString().c_str(), &binPubSrvX );
        if( strPublicServerY.length() > 0 ) JS_BIN_decodeHex( strPublicServerY.toStdString().c_str(), &binPubSrvY );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "AFT" )
        {
            if( strAlg == "kdf-components" )
            {
                ret = JS_PKI_KDF_X963( &binSecret, &binInfo, strUseHash.toStdString().c_str(), nKeyDataLength/8, &binKey );
                if( ret != 0 ) goto end;

                jRspTestObj["keyData"] = getHexString( &binKey );
            }
            else if( strAlg == "KAS-ECC" )
            {
                BIN binPri = {0,0};
                BIN binPub = {0,0};

                JECKeyVal sECKey;

                memset( &sECKey, 0x00, sizeof(sECKey));

                ret = JS_PKI_ECCGenKeyPair( strUseCurve.toStdString().c_str(), &binPub, &binPri );
                if( ret != 0 ) goto end;

                ret = JS_PKI_getECDHSecretWithValue( strUseCurve.toStdString().c_str(), &binPri, &binPubSrvX, &binPubSrvY, &binSecret );
                if( ret != 0 )
                {
                    JS_BIN_reset( &binPri );
                    JS_BIN_reset( &binPub );
                    goto end;
                }

                ret = JS_PKI_getECKeyVal( &binPri, &sECKey );

                jRspTestObj["publicIutX"] = sECKey.pPubX;
                jRspTestObj["publicIutY"] = sECKey.pPubY;
                jRspTestObj["z"] = getHexString( &binSecret );

                JS_PKI_resetECKeyVal( &sECKey );

                JS_BIN_reset( &binPri );
                JS_BIN_reset( &binPub );
            }
            else if( strAlg == "PBKDF" )
            {
                JS_BIN_decodeHex( strSalt.toStdString().c_str(), &binSalt );

                ret = JS_PKI_PBKDF2( strPassword.toStdString().c_str(), &binSalt, nIterCount, strUseHash.toStdString().c_str(), nKeyLen/8, &binDerivedKey );
                if( ret != 0 ) goto end;

                jRspTestObj["derivedKey"] = getHexString( &binDerivedKey );
            }
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binSecret );

    JS_BIN_reset( &binPubSrvX );
    JS_BIN_reset( &binPubSrvY );

    JS_BIN_reset( &binDerivedKey );
    JS_BIN_reset( &binSalt );

    return ret;
}

int CAVPDlg::drbgJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;
    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    int nAdditionalInputLen = jObject["additionalInputLen"].toInt();
    bool bDerFunc = jObject["derFunc"].toBool();
    QString strMode = jObject["mode"].toString();
    int nNonceLen = jObject["nonceLen"].toInt();
    int nPersoStringLen = jObject["persoStringLen"].toInt();
    bool bPredResistance = jObject["predResistance"].toBool();
    bool bReSeed = jObject["reSeed"].toBool();
    int nReturnedBitsLen = jObject["returnedBitsLen"].toInt();

    QString strMethod = QString( "%1-CTR").arg( strMode );

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    BIN binEntropyInput = {0,0};
    BIN binNonce = {0,0};
    BIN binPerso = {0,0};
    BIN binEntropyInputReseed = {0,0};
    BIN binAddReseed = {0,0};
    BIN binAddInput = {0,0};
    BIN binAddInput2 = {0,0};
    BIN binReturnedBits = {0,0};

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();

        QJsonObject jRspTestObj;
        jRspTestObj["tcId"] = nTcId;

        QString strEntropyInput = jObj["entropyInput"].toString();
        QString strNonce = jObj["nonce"].toString();
        QString strPersoString = jObj["persoString"].toString();

        JS_BIN_reset( &binEntropyInput );
        JS_BIN_reset( &binNonce );
        JS_BIN_reset( &binPerso );
        JS_BIN_reset( &binEntropyInputReseed );
        JS_BIN_reset( &binAddReseed );
        JS_BIN_reset( &binAddInput );
        JS_BIN_reset( &binAddInput2 );
        JS_BIN_reset( &binReturnedBits );

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        JS_BIN_decodeHex( strEntropyInput.toStdString().c_str(), &binEntropyInput );
        JS_BIN_decodeHex( strNonce.toStdString().c_str(), &binNonce );
        JS_BIN_decodeHex( strPersoString.toStdString().c_str(), &binPerso );

        QJsonArray jArrSub = jObj["otherInput"].toArray();
        for( int j = 0; j < jArrSub.size(); j++ )
        {
            QJsonValue jValSub = jArrSub.at(j);
            QJsonObject jObjSub = jValSub.toObject();

            QString strAdditionalInput = jObjSub["additionalInput"].toString();
            QString strEntropyInputSub = jObjSub["entropyInput"].toString();
            QString strIntendedUse = jObjSub["intendedUse"].toString();

            if( strIntendedUse == "reSeed" )
            {
                JS_BIN_decodeHex( strAdditionalInput.toStdString().c_str(), &binAddReseed );
                JS_BIN_decodeHex( strEntropyInputSub.toStdString().c_str(), &binEntropyInputReseed );
            }
            else
            {
                if( binAddInput.nLen <= 0 )
                    JS_BIN_decodeHex( strAdditionalInput.toStdString().c_str(), &binAddInput );
                else if( binAddInput2.nLen <= 0 )
                    JS_BIN_decodeHex( strAdditionalInput.toStdString().c_str(), &binAddInput2 );
                else
                {
                    ret = JSR_ERR;
                    goto end;
                }
            }
        }

        if( strTestType == "AFT" )
        {
            if( strAlg == "ctrDRBG" )
            {
                ret = JS_PKI_genCTR_DRBG( nReturnedBitsLen/8,
                                     bDerFunc,
                                     bPredResistance,
                                     strMethod.toStdString().c_str(),
                                     &binEntropyInput,
                                     &binNonce,
                                     &binPerso,
                                     &binEntropyInputReseed,
                                     &binAddReseed,
                                     &binAddInput,
                                     &binAddInput2,
                                     &binReturnedBits );
            }
            else if( strAlg == "hashDRBG" )
            {
                QString strUseHash = _getHashName( strMode );

                ret = JS_PKI_genHash_DRBG( nReturnedBitsLen/8,
                                         bPredResistance,
                                         strUseHash.toStdString().c_str(),
                                         &binEntropyInput,
                                         &binNonce,
                                         &binPerso,
                                         &binEntropyInputReseed,
                                         &binAddReseed,
                                         &binAddInput,
                                         &binAddInput2,
                                         &binReturnedBits );
            }
            else if( strAlg == "hmacDRBG" )
            {
                QString strUseHash = _getHashName( strMode );

                ret = JS_PKI_genHMAC_DRBG( nReturnedBitsLen/8,
                                         bPredResistance,
                                         strUseHash.toStdString().c_str(),
                                         &binEntropyInput,
                                         &binNonce,
                                         &binPerso,
                                         &binEntropyInputReseed,
                                         &binAddReseed,
                                         &binAddInput,
                                         &binAddInput2,
                                         &binReturnedBits );
            }
            else
            {
                ret = -1;
            }

            if( ret != 0 ) goto end;

            jRspTestObj["returnedBits"] = getHexString( &binReturnedBits );
        }
        else
        {
            berApplet->warnLog( tr("Invalid test type: %1").arg( strTestType), this );
            ret = -1;
            goto end;
        }

        if( mACVP_SetTCIDCheck->isChecked() == true )
            jRspArr.insert( 0, jRspTestObj );
        else
            jRspArr.insert( i, jRspTestObj );
    }

    jRspObject["tests"] = jRspArr;
    jRspObject["tgId"] = nTgId;

end :
    JS_BIN_reset( &binEntropyInput );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binPerso );
    JS_BIN_reset( &binEntropyInputReseed );
    JS_BIN_reset( &binAddReseed );
    JS_BIN_reset( &binAddInput );
    JS_BIN_reset( &binAddInput2 );
    JS_BIN_reset( &binReturnedBits );

    return ret;
}

void CAVPDlg::startLDTHash()
{
    mACVP_LDTProgressBar->setMaximum( 100 );
    mACVP_LDTProgressBar->setValue(0);

    mACVP_LDTStatusText->clear();
    mACVP_LDT_MDText->clear();

    QString strContent = mACVP_LDTContentText->text();
    QString strHash = mACVP_LDTHashCombo->currentText();
    QString strFullLength = mACVP_LDTFullLengthText->text();

    if( ldt_hash_ == nullptr )
    {
        ldt_hash_ = new LDTHashThread;

        connect( ldt_hash_, &LDTHashThread::taskFinished, this, &CAVPDlg::onLDTHashFinished );
        connect( ldt_hash_, &LDTHashThread::taskUpdate, this, &CAVPDlg::onLDTHashUpdate );
        connect( ldt_hash_, &LDTHashThread::taskLastUpdate, this, &CAVPDlg::onLDTHashLastUpdate );
    }

    ldt_hash_->setContent( strContent );
    ldt_hash_->setHash( strHash );
    ldt_hash_->setFullLengthBits( strFullLength.toLongLong());

    ldt_hash_->start();
}

void CAVPDlg::stopLDTHash()
{
    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure to stop?"), this, true );
    if( bVal == false ) return;

    if( ldt_hash_ == NULL ) return;

    ldt_hash_->setStop( true );
}

void CAVPDlg::onLDTHashFinished( int ret )
{
    berApplet->messageLog( QString( "LDT hash finished: %1").arg(ret), this );
}

void CAVPDlg::onLDTHashUpdate( qint64 nCurBits )
{
    QString strFullLength = mACVP_LDTFullLengthText->text();

    mACVP_LDTStatusText->setText( QString("%1").arg( nCurBits ));
    int nPercent = int( ( nCurBits * 100 ) / strFullLength.toLongLong() );

    mACVP_LDTProgressBar->setValue(nPercent);
}

void CAVPDlg::onLDTHashLastUpdate( const QString strMD )
{
    mACVP_LDT_MDText->setText( strMD );
}
