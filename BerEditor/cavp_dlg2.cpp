#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QFileInfo>

#include "cavp_dlg.h"
#include "common.h"
#include "ber_applet.h"

#include "js_pki.h"

const QString CAVPDlg::getPKI_Alg( const QString strACVP_Alg )
{
    if( strACVP_Alg == "SHA-1" )
        return "SHA1";
    else if( strACVP_Alg == "SHA2-224" )
        return "SHA224";
    else if( strACVP_Alg == "SHA2-256" )
        return "SHA256";
    else if( strACVP_Alg == "SHA2-384" )
        return "SHA384";
    else if( strACVP_Alg == "SHA2-512" )
        return "SHA512";
    else if( strACVP_Alg == "ECDSA" )
        return "ECC";
    else
        return "Not defined";
}

void CAVPDlg::clickACVPClear()
{
    mACVP_ReqPathText->clear();
    mACVP_StatusText->clear();
    mACVP_ProgressBar->setValue(0);
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
            int nVsId = jObj["vsId"].toInt();

            QJsonArray jTestGroupArr = jObj["testGroups"].toArray();

            jRspObj["algorithm"] = strAlg;
            jRspObj["revision"] = strRevision;
            jRspObj["vsId"] = nVsId;

            for( int k = 0; k < jTestGroupArr.size(); k++ )
            {
                QJsonValue jSubVal = jTestGroupArr.at(i);
                QJsonObject jSubObj = jSubVal.toObject();
                int nTgId = jSubObj["tgId"].toInt();
                QJsonObject jRspObject;

                if( mACVP_SetTGIDCheck->isChecked() == true )
                {
                    int nSetTgId = mACVP_SetTGIDText->text().toInt();
                    if( nSetTgId != nTgId ) continue;
                }

                ret = makeUnitJsonWork( strAlg, jSubObj, jRspObject );
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
        berApplet->warningBox( tr( "Enter a contentn" ), this );
        mACVP_LDTContentText->setFocus();
        return;
    }

    BIN binContent = {0,0};
    BIN binMD = {0,0};

    qint64 nFullLenght = strFullLength.toLongLong();
    qint64 nCurLength = 0;

    mACVP_ProgressBar->setValue(0);

    JS_BIN_decodeHex( strContent.toStdString().c_str(), &binContent );

    ret = JS_PKI_hashInit( &pCTX, strHash.toStdString().c_str() );
    if( ret != 0 ) goto end;

    while( nFullLenght > nCurLength )
    {
        int nPercent = 0;

        ret = JS_PKI_hashUpdate( pCTX, &binContent );
        if( ret != 0 ) goto end;

        nCurLength += binContent.nLen;

        nPercent = ( nCurLength * 100 ) / nFullLenght;
        mACVP_ProgressBar->setValue( nPercent );
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

}

void CAVPDlg::clickACVP_LDTThreadStop()
{

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
    if( strPath.length() < 1 ) strPath = berApplet->curFile();

    QString strFile = findFile( this, JS_FILE_TYPE_JSON, strPath );
    if( strFile.length() > 0 )
    {
        mACVP_ReqPathText->setText( strFile );
        berApplet->setCurFile( strFile );
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
    QString strRspPath = mRspPathText->text();
    QString strReqPath = mACVP_ReqPathText->text();

    QFileInfo fileInfo( strReqPath );
    QString strBaseName = fileInfo.baseName();

    QString strSaveName;

    if( strRspPath.length() > 0 ) strRspPath += "/";

    strSaveName = QString( "%1/%2_rsp.json" ).arg( strRspPath ).arg( strBaseName );
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

int CAVPDlg::makeUnitJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    int ret = 0;

    QString strTestType = jObject["testType"].toString();
    int nTgId = jObject["tgId"].toInt();

    QJsonArray jArr = jObject["tests"].toArray();
    QJsonArray jRspArr;

    if( strAlg == "SHA-1" || strAlg == "SHA2-224" || strAlg == "SHA2-256" || strAlg == "SHA2-384" || strAlg == "SHA2-512" )
        ret = hashJsonWork( getPKI_Alg( strAlg ), jObject, jRspObject );
    else if( strAlg == "ECDSA" )
        ret = ecdsaJsonWork( getPKI_Alg( strAlg ), jObject, jRspObject );
    else
    {
        ret = -1;
        berApplet->warnLog( QString( "Invalid Algorithm: %1" ).arg( strAlg ), this );
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

    for( int i = 0; i < jArr.size(); i++ )
    {
        QJsonValue jVal = jArr.at(i);
        QJsonObject jObj = jVal.toObject();
        int nTcId = jObj["tcId"].toInt();
        QString strMsg = jObj["msg"].toString();

        QJsonObject jRspTestObj;

        jRspTestObj["tcId"] = nTcId;

        if( mACVP_SetTCIDCheck->isChecked() == true )
        {
            int nSetTcId = mACVP_SetTCIDText->text().toInt();
            if( nSetTcId != nTcId ) continue;
        }

        if( strTestType == "LDT" )
        {

        }
        else if( strTestType == "MCT" )
        {
            QJsonArray jMDArr;

            if( strMctVersion == "alternate" )
                makeHashAlternateMCT( strAlg.toStdString().c_str(), strMsg, &jMDArr );
            else
                makeHashMCT( strAlg.toStdString().c_str(), strMsg, &jMDArr );

            jRspTestObj["resultsArray"] = jMDArr;
        }
        else
        {
            ret = JS_PKI_genHash( strAlg.toStdString().c_str(), &binMsg, &binMD );
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

int CAVPDlg::ecdsaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::rsaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::macJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::blockCipherJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}

int CAVPDlg::kdaJsonWork( const QString strAlg, const QJsonObject jObject, QJsonObject& jRspObject )
{
    return 0;
}
