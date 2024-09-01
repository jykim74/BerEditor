#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QFileInfo>

#include "cavp_dlg.h"
#include "common.h"
#include "ber_applet.h"

#include "js_pki.h"

void CAVPDlg::clickACVPClear()
{
    mACVP_ReqPathText->clear();
    mACVP_StatusInfoText->clear();
    mACVP_ProgressBar->setValue(0);
}

void CAVPDlg::clickACVPRun()
{

}

void CAVPDlg::clickACVPThreadRun()
{

}

void CAVPDlg::clickACVPThreadStop()
{

}

void CAVPDlg::clickACVP_LDTClear()
{
    mACVP_LDTContentText->clear();
    mACVP_LDTFullLengthText->clear();
    mACVP_LDT_MDText->clear();
    mACVP_LDTStatusText->clear();
    mACVP_ProgressBar->setValue(0);
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

void CAVPDlg::saveJsonRsp()
{
    QString strRspPath = mRspPathText->text();
    QString strReqPath = mACVP_ReqPathText->text();

    QFileInfo fileInfo( strReqPath );
    QString strBaseName = fileInfo.baseName();

    QString strSaveName;

    if( strRspPath.length() > 0 ) strRspPath += "/";

    strSaveName = QString( "%1/%2_rsp.json" ).arg( strRspPath ).arg( strBaseName );
}
