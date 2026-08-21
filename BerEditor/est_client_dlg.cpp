#include <QSettings>

#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "cert_man_dlg.h"
#include "new_passwd_dlg.h"
#include "pri_key_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_http.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"

#include "est_client_dlg.h"

const QString kESTUsedURL = "ESTUsedURL";
const QStringList kESTCmdList = {
    kEST_CACerts, kEST_SimpleEnroll, kEST_SimpleReenroll,
    kEST_FullCMC, kEST_ServerKeyGen, kEST_CSRAttrs
};


ESTClientDlg::ESTClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmd()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));

    connect( mCAFindBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mCAViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCADecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCATypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));

    connect( mCertFindBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(viewPriKey()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));

    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mGetCABtn, SIGNAL(clicked()), this, SLOT(clickGetCA()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
    mCertGroup->layout()->setSpacing(5);

    mCAViewBtn->setFixedWidth(34);
    mCADecodeBtn->setFixedWidth(34);
    mCATypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mPriKeyDecodeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);
    mPriKeyViewBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
    mGetCABtn->setDefault(true);
}

ESTClientDlg::~ESTClientDlg()
{

}

void ESTClientDlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void ESTClientDlg::initUI()
{
    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );
    mURLCombo->setFocus();

    mCmdCombo->addItems( kESTCmdList );
    changeCmd();
}

void ESTClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    checkEncPriKey();

    mCACertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));

    mPriKeyPathText->setPlaceholderText( tr("Select CertMan private key") );
    mCertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));
    mRequestText->setPlaceholderText( tr("String value" ));
    mResponseText->setPlaceholderText( tr("String value" ));
}

QStringList ESTClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kESTUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void ESTClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kESTUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kESTUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

int ESTClientDlg::getCA( BIN *pCA )
{
    int ret = 0;

    QString strCAPath = mCACertPathText->text();

    if( strCAPath.length() < 1 ) return -1;

    ret = getDataFromURI( strCAPath, pCA );

    return ret;
}

int ESTClientDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mPriKeyPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        mPriKeyPathText->setFocus();
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "failed to decrypt private key:%1").arg( ret ), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_copy( pPriKey, &binDec );
        ret = 0;
    }
    else
    {
        JS_BIN_copy( pPriKey, &binData );
        ret = 0;
    }

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );

    return ret;
}

void ESTClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kESTUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void ESTClientDlg::changeCmd()
{
    QString strCmd = mCmdCombo->currentText();
}

void ESTClientDlg::clickMake()
{
    QString strCmd = mCmdCombo->currentText();

    if( strCmd == kEST_CACerts )
        clickMakeCACerts();
    else if( strCmd == kEST_SimpleEnroll )
        clickMakeSimpleEnroll();
    else if( strCmd == kEST_SimpleReenroll )
        clickMakeSimpleReenroll();
    else if( strCmd == kEST_FullCMC )
        clickMakeFullCMC();
    else if( strCmd == kEST_ServerKeyGen )
        clickMakeServerKeyGen();
    else if( strCmd == kEST_CSRAttrs )
        clickMakeCSRAttrs();
}

void ESTClientDlg::clickMakeCACerts()
{

}

void ESTClientDlg::clickMakeSimpleEnroll()
{
    int ret = 0;
    GenKeyPairDlg genKeyPair;
    MakeCSRDlg makeCSR;

    BIN binPriKey = {0,0};
    BIN binPubKey = {0,0};
    BIN binCSR = {0,0};

    QString strHex;
    char *pPEM = NULL;

    genKeyPair.setFixName( tr("EST SimpleEnroll KeyPair" ));
    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binPriKey );

    makeCSR.setPriKey( &binPriKey );
    if( makeCSR.exec() != QDialog::Accepted ) goto end;

    strHex = makeCSR.getCSRHex();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binCSR );

    JS_BIN_encodePEM( JS_PEM_TYPE_CSR, &binCSR, &pPEM );

    mRequestText->setPlainText( pPEM );

end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binPubKey );
    JS_BIN_reset( &binCSR );
    if( pPEM ) JS_free( pPEM );
}

void ESTClientDlg::clickMakeSimpleReenroll()
{
    int ret = 0;
    BIN binPriKey = {0,0};
    BIN binPubKey = {0,0};
    BIN binCert = {0,0};

    BIN binNewPri = {0,0};
    BIN binNewPub = {0,0};
    BIN binCSR = {0,0};

    int nKeyType = -1;
    int nParam = -1;
    JCertInfo sCertInfo;
    QString strHex;
    char *pPEM = NULL;

    if( mCertGroup->isChecked() == true )
    {
        QString strCertPath = mCertPathText->text();
        if( strCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a certificate" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
        ret = readPrivateKey( &binPriKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPriKey );
        certMan.getCert( &binCert );
    }


    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_PKI_getPubKeyInfo( &binPubKey, &nKeyType, &nParam );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_PKI_genKeyPair( nKeyType, nParam, 65537, &binNewPub, &binNewPri );
    if( ret != JSR_OK )
    {
        goto end;
    }

    ret = JS_PKI_makeCSR( "SHA256", sCertInfo.pSubjectName, NULL, NULL, &binNewPri, NULL, &binCSR );
    if( ret != 0 )
    {
        goto end;
    }

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binCSR );

    JS_BIN_encodePEM( JS_PEM_TYPE_CSR, &binCSR, &pPEM );

    mRequestText->setPlainText( pPEM );

end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binPubKey );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCSR );

    JS_BIN_reset( &binNewPri );
    JS_BIN_reset( &binNewPub );

    JS_PKI_resetCertInfo( &sCertInfo );
    if( pPEM ) JS_free( pPEM );
}

void ESTClientDlg::clickMakeFullCMC()
{

}

void ESTClientDlg::clickMakeServerKeyGen()
{

}

void ESTClientDlg::clickMakeCSRAttrs()
{

}

void ESTClientDlg::savePriKeyCert( const BIN *pPriKey, const BIN *pCert )
{
    int ret = 0;

    bool bVal = false;
    bVal = berApplet->yesOrNoBox( tr( "Do you want to save the private key and certificate"), this, true );
    if( bVal == true )
    {
        int nKeyType = -1;
        BIN binEncPri = {0,0};
        CertManDlg certMan;
        NewPasswdDlg newPass;

        if( newPass.exec() == QDialog::Accepted )
        {
            QString strPass = newPass.mPasswdText->text();
            int nPBE = JS_PKI_getNidFromSN( berApplet->settingsMgr()->priEncMethod().toStdString().c_str() );

            nKeyType = JS_PKI_getPriKeyType( pPriKey );

            ret = JS_PKI_encryptPrivateKey( nPBE, strPass.toStdString().c_str(), pPriKey, NULL, &binEncPri );
            if( ret == 0 )
            {
                ret = certMan.writePriKeyCert( &binEncPri, pCert );
                if( ret == 0 )
                    berApplet->messageLog( tr( "The private key and certificate are saved successfully" ), this );
                else
                    berApplet->warnLog( tr( "failed to save the private key and certificate" ), this );
            }
        }

        JS_BIN_reset( &binEncPri );
    }
}

void ESTClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCACertPathText->setText( filePath );
    }
}

void ESTClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCertPathText->setText( filePath );
    }
}

void ESTClientDlg::findPriKey()
{
    QString strPath = mPriKeyPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 )
    {
        mPriKeyPathText->setText( filePath );
    }
}

void ESTClientDlg::typeCACert()
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

    getDataFromURI( strFile, &binData );
    //    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void ESTClientDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void ESTClientDlg::typePriKey()
{
    int nType = -1;
    BIN binPri = {0,0};

    int ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nType = JS_PKI_getPriKeyType( &binPri );
    berApplet->messageBox( tr( "The private key type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void ESTClientDlg::viewCACert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

    getDataFromURI( strFile, &binData );
    //    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void ESTClientDlg::viewCert()
{
    CertInfoDlg certInfo;
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mCertPathText->setFocus();
        return;
    }

    certInfo.setCertPath( strFile );
    certInfo.exec();
}

void ESTClientDlg::viewPriKey()
{
    int ret = 0;
    BIN binPri = {0,0};

    PriKeyInfoDlg priKeyInfo;

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void ESTClientDlg::decodeCACert()
{
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

    getDataFromURI( strFile, &binData );
    //    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void ESTClientDlg::decodeCert()
{
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void ESTClientDlg::decodePriKey()
{
    BIN binData = {0,0};
    QString strFile = mPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a private key" ), this );
        mPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void ESTClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();

    if( strHex.length() < 1)
    {
        berApplet->warningBox( tr( "No request available" ), this );
        mRequestText->setFocus();
        return;
    }

    int ret = getBINFromString( &binData, DATA_HEX, strHex );
    FORMAT_WARN_GO(ret);

    berApplet->decodeTitle( &binData, "EST Request" );
end :
    JS_BIN_reset( &binData );
}

void ESTClientDlg::decodeResponse()
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

    berApplet->decodeTitle( &binData, "EST Response" );
    JS_BIN_reset( &binData );
}

void ESTClientDlg::clearRequest()
{
    mRequestText->clear();
}

void ESTClientDlg::clearResponse()
{
    mResponseText->clear();
}

void ESTClientDlg::requestChanged()
{
    QString strLen = getDataLenString( DATA_STRING, mRequestText->toPlainText() );
    mRequestLenText->setText( QString("%1").arg( strLen ) );
}

void ESTClientDlg::responseChanged()
{
    QString strLen = getDataLenString( DATA_STRING, mResponseText->toPlainText() );
    mResponseLenText->setText( QString("%1").arg( strLen ) );
}

void ESTClientDlg::clickClearAll()
{
    clearRequest();
    clearResponse();
}

void ESTClientDlg::clickGetCA()
{
    int ret = 0;
    int nStatus = 0;

    BIN binRSP = {0,0};
    QString strURL = mURLCombo->currentText();

    CertInfoDlg certInfo;
    char *pRsp = NULL;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter EST URL"), this );
        return;
    }

    strURL += "/";
    strURL += kEST_CACerts;

    ret = JS_HTTP_requestGetBin2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        &nStatus,
        &binRSP );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP get [%1:%2]").arg(ret).arg(nStatus), this );
        goto end;
    }

    JS_BIN_string( &binRSP, &pRsp );

    mResponseText->setPlainText( pRsp );

#if 0
    if( mCACertPathText->text().length() < 1 )
        mCACertPathText->setText( strURL );

    certInfo.setCertBIN( &binRSP );
    certInfo.exec();
#endif

end :
    JS_BIN_reset( &binRSP );
    if( pRsp ) JS_free( pRsp );
}

void ESTClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binDER = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strReq = mRequestText->toPlainText();
    QString strLink;
    QString strCmd = mCmdCombo->currentText();

    CertInfoDlg certInfo;
    char *pRsp = NULL;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter EST URL"), this );
        return;
    }

    strLink = strURL;
    strLink += ";";
    strLink += strCmd;

    if( strReq.length() > 0 )
    {
        JS_BIN_set( &binReq, (unsigned char *)strReq.toStdString().c_str(), strReq.length() );

        ret = JS_HTTP_requestPostBin2(
            strLink.toStdString().c_str(),
            NULL,
            NULL,
            "application/pkcs10",
            &binReq,
            &nStatus,
            &binRsp );
    }
    else
    {
        ret = JS_HTTP_requestGetBin2(
            strLink.toStdString().c_str(),
            NULL,
            NULL,
            &nStatus,
            &binRsp );
    }

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

//    JS_BIN_formatToBIN( &binRsp, &binDER );

    JS_BIN_string( &binRsp, &pRsp );
    mResponseText->setPlainText( pRsp );
    setUsedURL( strURL );
    berApplet->messageBox( tr("EST message sent"), this );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binDER );
    if( pRsp ) JS_free( pRsp );
}

void ESTClientDlg::clickVerify()
{

}
