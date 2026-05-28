#include <QSettings>

#include "tsp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "tst_info_dlg.h"
#include "cert_man_dlg.h"
#include "cms_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_tsp.h"
#include "js_http.h"
#include "js_error.h"
#include "js_pkcs7.h"

const QString kTSPUsedURL = "TSPUsedURL";


TSPClientDlg::TSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mTSTInfoBtn, SIGNAL(clicked()), this, SLOT(clickTSTInfo()));
    connect( mViewCMSBtn, SIGNAL(clicked()), this, SLOT(clickViewCMS()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifySignedBtn, SIGNAL(clicked()), this, SLOT(clickVerifySigned()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);

    mResponseDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);

#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
    mEncodeBtn->setDefault(true);
}

TSPClientDlg::~TSPClientDlg()
{

}

void TSPClientDlg::initUI()
{
    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );
    mURLCombo->setFocus();
}

void TSPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mInputTypeCombo->addItems( kDataTypeList );

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    mPolicyText->setPlaceholderText( tr("Object Identifier") );

    mRequestText->setPlaceholderText( tr("Hex value" ));
    mResponseText->setPlaceholderText( tr("Hex value" ));
}

QStringList TSPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void TSPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTSPUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

void TSPClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTSPUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void TSPClientDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( mInputTypeCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void TSPClientDlg::requestChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mRequestText->toPlainText() );
    mRequestLenText->setText( QString("%1").arg( strLen ) );
}

void TSPClientDlg::responseChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mResponseText->toPlainText() );
    mResponseLenText->setText( QString("%1").arg( strLen ) );
}

void TSPClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();

    if( strHex.length() < 1)
    {
        berApplet->warningBox( tr( "No request available" ), this );
        mRequestText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );
    int ret = getBINFromString( &binData, DATA_HEX, strHex );
    FORMAT_WARN_GO(ret);

    berApplet->decodeTitle( &binData, "TSP Request"  );
end:
    JS_BIN_reset( &binData );
}

void TSPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();

    if( strHex.length() < 1)
    {
        berApplet->warningBox( tr( "There is no response" ), this );
        mResponseText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );
    berApplet->decodeTitle( &binData, "TSP Response" );

    JS_BIN_reset( &binData );
}


void TSPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void TSPClientDlg::clearResponse()
{
    mResponseText->clear();
}

void TSPClientDlg::clickMake()
{
    int ret = 0;

    BIN binInput = {0,0};
    BIN binHash = {0,0};
    QString strHash = mHashCombo->currentText();
    QString strInput = mInputText->toPlainText();

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no input" ), this );
        mInputText->setFocus();
        return;
    }

    ret = getBINFromString( &binInput, mInputTypeCombo->currentText(), strInput );
    FORMAT_WARN_GO(ret);

    JS_PKI_genHash( strHash.toStdString().c_str(), &binInput, &binHash );

    mHashText->setText( getHexString(&binHash));

end :
    JS_BIN_reset( &binInput );
    JS_BIN_reset( &binHash );
}

void TSPClientDlg::clickEncode()
{
    int ret = 0;
    BIN binReq = {0,0};
    BIN binInput = {0,0};
    QString strHash = mHashCombo->currentText();
    QString strInput = mInputText->toPlainText();
    QString strPolicy = mPolicyText->text();
    const char *pPolicy = NULL;
    int nUseNonce = 0;


    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no input" ), this );
        mInputText->setFocus();
        return;
    }


/*
    if( strPolicy.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert policy OID" ), this );
        mPolicyText->setFocus();
        return;
    }
*/
    ret = getBINFromString( &binInput, mInputTypeCombo->currentText(), strInput );
    FORMAT_WARN_GO(ret);

    if( strPolicy.length() > 0 ) pPolicy = strPolicy.toStdString().c_str();

    if( mUseNonceCheck->isChecked() == true )
        nUseNonce = 1;

    ret = JS_TSP_encodeRequest( &binInput, strHash.toStdString().c_str(), pPolicy, nUseNonce, &binReq );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to encode TSP request: %1").arg( JERR(ret) ), this);
        goto end;
    }

    mRequestText->setPlainText( getHexString( &binReq ));
    berApplet->messageBox( tr("TSP message encoded" ), this );
    if( mAutoSendCheck->isChecked() == true ) clickSend();

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binInput );
}

void TSPClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binDER = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strURL = mURLCombo->currentText();

    QString strAuth;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert TSP URL"), this );
        goto end;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("No request available" ), this );
        goto end;
    }

    if( mAuthGroup->isChecked() == true )
    {
        QString strUser = mUserText->text();
        QString strPass = mPassText->text();
        QString strUP;
        BIN bin = {0,0};
        char *pBase64 = NULL;

        if( strUser.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a username" ), this );
            mUserText->setFocus();
            return;
        }

        if( strPass.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPassText->setFocus();
            return;
        }

        strUP = QString( "%1:%2" ).arg( strUser ).arg( strPass );
        JS_BIN_set( &bin, (unsigned char *)strUP.toStdString().c_str(), strUP.length() );
        JS_BIN_encodeBase64( &bin, &pBase64 );
        strAuth = QString( "Basic %1").arg( pBase64 );

        JS_BIN_reset( &bin );
        if( pBase64 ) JS_free( pBase64 );
    }

    ret = getBINFromString( &binReq, DATA_HEX, strReq );
    FORMAT_WARN_GO(ret);

    if( mAuthGroup->isChecked() == true )
        ret = JS_HTTP_requestAuthPostBin( strURL.toStdString().c_str(), "application/tsp-request", strAuth.toStdString().c_str(), &binReq, &nStatus, &binRsp );
    else
        ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );

    if( ret == 0 && nStatus == JS_HTTP_STATUS_OK )
    {
        JS_BIN_formatToBIN( &binRsp, &binDER );
        mResponseText->setPlainText( getHexString( &binDER ));
        setUsedURL( strURL );
        berApplet->messageBox( tr("TSP message sent"), this );
    }
    else
    {
        berApplet->warnLog( tr( "failed to send a request to TSP server: %1 (STATUS: %2)").arg(JERR(ret)).arg( nStatus ), this );
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binDER );
}

void TSPClientDlg::clickVerify()
{
    int ret = 0;
    BIN binCA = {0,0};
    BIN binSrvCert = {0,0};
    BIN binRsp = {0,0};
    BIN binData = {0,0};

    QString strRspHex = mResponseText->toPlainText();
    QString strCAManPath = berApplet->settingsMgr()->CACertPath();
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();

    JTSTInfo    sTSTInfo;
    char        sResMsg[1024];

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));
    memset( sResMsg, 0x00, sizeof(sResMsg));

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    if( mCertCheck->isChecked() == true )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select TSP server certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binSrvCert );
    };

    if( binSrvCert.nLen > 0 )
    {
        CertInfoDlg::getCA2( &binSrvCert, berApplet->settingsMgr()->onlineCA_CRL(), &binCA );
    }

    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_TSP_verifyResponse( &binRsp,
                                mCAListCheck->isChecked() ? strCAManPath.toLocal8Bit().toStdString().c_str() : NULL,
                                mTrustListCheck->isChecked() ? strTrustPath.toLocal8Bit().toStdString().c_str() : NULL,
                                &binCA,
                                &binSrvCert, &binData, &sTSTInfo, sResMsg );
    if( ret == JSR_VERIFY )
    {
        berApplet->messageLog( tr( "verify reponse successfully"), this );
    }
    else
    {
        berApplet->warnLog( tr( "failed to verify signature: %1(%2)").arg(JERR(ret)).arg(sResMsg), this );
    }

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binSrvCert );
    JS_BIN_reset( &binData );
    JS_TSP_resetTSTInfo( &sTSTInfo );
}

void TSPClientDlg::clickVerifySigned()
{
    int ret = 0;

    BIN binSrvCert = {0,0};
    BIN binRsp = {0,0};
    BIN binSigned = {0,0};
    BIN binTST = {0,0};
    BIN binMsg = {0,0};

    QString strRspHex = mResponseText->toPlainText();
    QString strCAManPath = berApplet->settingsMgr()->CACertPath();
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();

    int nFlags = -1;
    int nStatus = 0;

    char sResMsg[1024];
    time_t check_t = time(NULL);

    memset( sResMsg, 0x00, sizeof(sResMsg));

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    if( mCertCheck->isChecked() == true )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select TSP server certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binSrvCert );
    }

    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_TSP_decodeResponse( &binRsp, &nStatus, &binSigned, &binTST );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "failed to decode TSP response: %1 (STATUS: %2)")
                                  .arg( JERR(ret)).arg( nStatus ), this );
        goto end;
    }

    ret = JS_PKCS7_verifySignedData(
        &binSigned,
        &binSrvCert,
        NULL,
        nFlags,
        check_t,
        mCAListCheck->isChecked() ? berApplet->settingsMgr()->CACertPath().toLocal8Bit().toStdString().c_str() : NULL,
        mTrustListCheck->isChecked() ? berApplet->settingsMgr()->trustCertPath().toLocal8Bit().toStdString().c_str() : NULL,
        &binMsg,
        sResMsg );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageLog( tr( "Verify OK"), this );
    }
    else
    {
        berApplet->warnLog( QString( "failed to verify: %1(%2)").arg(JERR(ret)).arg(sResMsg), this );
    }

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSrvCert );
    JS_BIN_reset( &binSigned );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binMsg );
}

void TSPClientDlg::clickTSTInfo()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binTST = {0,0};
    BIN binRsp = {0,0};

    TSTInfoDlg tstInfo;
    int nStatus = 0;

    QString strOut = mResponseText->toPlainText();
    if( strOut.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no TSP response" ), this );
        mResponseText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &nStatus, &binData, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox(tr( "TSP Response error: %1").arg(JERR(ret)), this );
        goto end;
    }

    tstInfo.setTST( &binTST );
    tstInfo.exec();

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
}

void TSPClientDlg::clickViewCMS()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binTST = {0,0};
    BIN binRsp = {0,0};

    CMSInfoDlg cmsInfo;
    int nStatus = 0;

    QString strOut = mResponseText->toPlainText();
    if( strOut.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no TSP response" ), this );
        mResponseText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &nStatus, &binData, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox(tr( "TSP Response error: %1").arg(JERR(ret)), this );
        goto end;
    }

    cmsInfo.setCMS( &binData );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
}

void TSPClientDlg::clickClearAll()
{
    mInputText->clear();
    mHashText->clear();
    clearRequest();
    clearResponse();
}
