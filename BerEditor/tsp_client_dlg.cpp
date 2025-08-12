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

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mTSTInfoBtn, SIGNAL(clicked()), this, SLOT(clickTSTInfo()));
    connect( mViewCMSBtn, SIGNAL(clicked()), this, SLOT(clickViewCMS()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));

    connect( mFindSrvCertBtn, SIGNAL(clicked()), this, SLOT(findSrvCert()));
    connect( mSelectSrvCertBtn, SIGNAL(clicked()), this, SLOT(selectSrvCert()));
    connect( mSrvCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSrvCert()));
    connect( mSrvCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSrvCert()));
    connect( mSrvCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSrvCert()));

    connect( mFindCACertBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCACertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mVerifySignedBtn, SIGNAL(clicked()), this, SLOT(clickVerifySigned()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mSrvCertDecodeBtn->setFixedWidth(34);
    mSrvCertViewBtn->setFixedWidth(34);
    mSrvCertTypeBtn->setFixedWidth(34);

    mCACertDecodeBtn->setFixedWidth(34);
    mCACertViewBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

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

void TSPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mInputTypeCombo->addItems( kValueTypeList );

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    mPolicyText->setPlaceholderText( "1.2.3.4" );

    mCACertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));
    mSrvCertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));
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
        berApplet->warningBox( tr( "There is no request" ), this );
        mRequestText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, "TSP Request" );

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

    berApplet->decodeData( &binData, "TSP Response" );

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

void TSPClientDlg::findSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mSrvCertPathText->setText( filePath );
    }
}

void TSPClientDlg::selectSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    if( strPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select TSP certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return;

        strPath = certMan.getSeletedCertPath();
        if( strPath.length() < 1 )
        {
            berApplet->warningBox( "Select TSP certificate", this );
            return;
        }
        else
        {
            mSrvCertPathText->setText( strPath );
        }
    }
}

void TSPClientDlg::viewSrvCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        mSrvCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void TSPClientDlg::decodeSrvCert()
{
    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        mSrvCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void TSPClientDlg::typeSrvCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        mSrvCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void TSPClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCACertPathText->setText( filePath );
    }
}

void TSPClientDlg::viewCACert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void TSPClientDlg::decodeCACert()
{
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void TSPClientDlg::typeCACert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
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
    getBINFromString( &binInput, mInputTypeCombo->currentText(), strInput );

    if( strPolicy.length() > 0 ) pPolicy = strPolicy.toStdString().c_str();

    if( mUseNonceCheck->isChecked() == true )
        nUseNonce = 1;

    ret = JS_TSP_encodeRequest( &binInput, strHash.toStdString().c_str(), pPolicy, nUseNonce, &binReq );
    if( ret != 0 )
    {
        berApplet->elog( QString("failed to encode TSP request [%1]").arg( ret ));
        goto end;
    }

    mRequestText->setPlainText( getHexString( &binReq ));

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
        berApplet->warningBox( tr("There is no request" ), this );
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

    getBINFromString( &binReq, DATA_HEX, strReq );

    if( mAuthGroup->isChecked() == true )
        ret = JS_HTTP_requestAuthPostBin( strURL.toStdString().c_str(), "application/tsp-request", strAuth.toStdString().c_str(), &binReq, &nStatus, &binRsp );
    else
        ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );

    if( ret == 0 )
    {
        mResponseText->setPlainText( getHexString( &binRsp ));
        setUsedURL( strURL );
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to TSP server: %1").arg( ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void TSPClientDlg::clickVerify()
{
    int ret = 0;
    BIN binCA = {0,0};
    BIN binSrvCert = {0,0};
    BIN binRsp = {0,0};
    BIN binData = {0,0};

    QString strCAPath = mCACertPathText->text();
    QString strSrvCertPath = mSrvCertPathText->text();
    QString strRspHex = mResponseText->toPlainText();
    QString strCAManPath = berApplet->settingsMgr()->CACertPath();
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();

    JTSTInfo    sTSTInfo;

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    if( strCAPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCA);
        certMan.setTitle( tr( "Select CA certificate" ));
        certMan.exec();

        strCAPath = certMan.getSeletedCAPath();
        if( strCAPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a CA certificate" ), this );
            mCACertPathText->setFocus();
            return;
        }
        else
        {
            mCACertPathText->setText( strCAPath );
        }
    }

    if( strSrvCertPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select TSP server certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strSrvCertPath = certMan.getSeletedCertPath();
        if( strSrvCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a TSP server certificate"), this );
            goto end;
        }
        else
        {
            mSrvCertPathText->setText( strSrvCertPath );
        }
    }

    if( strCAPath.length() > 0 )
        JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );


    if( strSrvCertPath.length() > 0 )
        JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );
    JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );
    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_TSP_verifyResponse( &binRsp,
                                strCAManPath.toLocal8Bit().toStdString().c_str(),
                                strTrustPath.toLocal8Bit().toStdString().c_str(),
                                &binCA,
                                &binSrvCert, &binData, &sTSTInfo );
    if( ret == JSR_VERIFY )
    {
        berApplet->messageLog( tr( "verify reponse successfully"), this );
    }
    else if( ret == JSR_INVALID )
    {
        berApplet->warnLog( tr( "failed to verify signature"), this );
    }
    else
    {
        berApplet->warnLog( QString( "failed to verify response message [%1]").arg(ret), this );
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

    QString strSrvCertPath = mSrvCertPathText->text();
    QString strRspHex = mResponseText->toPlainText();
    QString strCAManPath = berApplet->settingsMgr()->CACertPath();
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();

    if( strSrvCertPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select TSP server certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strSrvCertPath = certMan.getSeletedCertPath();
        if( strSrvCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a TSP server certificate"), this );
            goto end;
        }
        else
        {
            mSrvCertPathText->setText( strSrvCertPath );
        }
    }

    if( strSrvCertPath.length() > 0 )
        JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );
    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_TSP_decodeResponse( &binRsp, &binSigned, &binTST );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "failed to decode TSP response"), this );
        goto end;
    }

    ret = JS_PKCS7_verifySignedData( &binSigned, &binSrvCert, &binMsg );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageLog( tr( "verify reponse successfully"), this );
    }
    else if( ret == JSR_INVALID )
    {
        berApplet->warnLog( tr( "failed to verify signature"), this );
    }
    else
    {
        berApplet->warnLog( QString( "failed to verify response message [%1]").arg(ret), this );
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

    QString strOut = mResponseText->toPlainText();
    if( strOut.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no TSP response" ), this );
        mResponseText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "failed to decode TSP response"), this );
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

    QString strOut = mResponseText->toPlainText();
    if( strOut.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no TSP response" ), this );
        mResponseText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "failed to decode TSP response"), this );
        goto end;
    }

    cmsInfo.setCMS( &binData );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
}
