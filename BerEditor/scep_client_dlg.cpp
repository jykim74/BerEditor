#include <QSettings>

#include "scep_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "cert_man_dlg.h"
#include "new_passwd_dlg.h"
#include "pri_key_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_scep.h"
#include "js_http.h"
#include "js_pki_x509.h"

const QString kSCEPUsedURL = "SCEPUsedURL";

SCEPClientDlg::SCEPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);


    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

    connect( mFindCACertBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCACertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));

    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(viewPriKey()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));

    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mGetCABtn, SIGNAL(clicked()), this, SLOT(clickGetCA()));
    connect( mMakeIssueBtn, SIGNAL(clicked()), this, SLOT(clickMakeIssue()));
    connect( mMakeUpdateBtn, SIGNAL(clicked()), this, SLOT(clickMakeUpdate()));
    connect( mMakeGetCRLBtn, SIGNAL(clicked()), this, SLOT(clickMakeGetCRL()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mNonceText, SIGNAL(textChanged(QString)), this, SLOT(changeNonce(QString)));
    connect( mTransIDText, SIGNAL(textChanged(QString)), this, SLOT(changeTransID(QString)));

    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
    mCertGroup->layout()->setSpacing(5);

    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

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

SCEPClientDlg::~SCEPClientDlg()
{

}

void SCEPClientDlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void SCEPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    JS_SCEP_init();
    checkEncPriKey();

    mCACertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));

    mPriKeyPathText->setPlaceholderText( tr("Select CertMan private key") );
    mCertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));
    mRequestText->setPlaceholderText( tr("Hex value" ));
    mResponseText->setPlaceholderText( tr("Hex value" ));
}

QStringList SCEPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kSCEPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void SCEPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kSCEPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kSCEPUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

int SCEPClientDlg::getCA( BIN *pCA )
{
    int ret = 0;

    QString strCAPath = mCACertPathText->text();

    if( strCAPath.length() < 1 ) return -1;

    ret = getDataFromURI( strCAPath, pCA );

    return ret;
}

int SCEPClientDlg::readPrivateKey( BIN *pPriKey )
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

void SCEPClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kSCEPUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void SCEPClientDlg::savePriKeyCert( const BIN *pPriKey, const BIN *pCert )
{
    int ret = 0;

    bool bVal = false;
    bVal = berApplet->yesOrNoBox( tr( "Are you save the private key and certificate"), this, true );
    if( bVal == true )
    {
        int nKeyType = -1;
        BIN binEncPri = {0,0};
        CertManDlg certMan;
        NewPasswdDlg newPass;

        if( newPass.exec() == QDialog::Accepted )
        {
            QString strPass = newPass.mPasswdText->text();
            nKeyType = JS_PKI_getPriKeyType( pPriKey );

            ret = JS_PKI_encryptPrivateKey( -1, strPass.toStdString().c_str(), pPriKey, NULL, &binEncPri );
            if( ret == 0 )
            {
                ret = certMan.writePriKeyCert( &binEncPri, pCert );
                if( ret == 0 )
                    berApplet->messageLog( tr( "The private key and certificate are saved successfully" ), this );
                else
                    berApplet->warnLog( tr( "faied to save private key and certificate" ), this );
            }
        }

        JS_BIN_reset( &binEncPri );
    }
}

void SCEPClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCACertPathText->setText( filePath );
    }
}

void SCEPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCertPathText->setText( filePath );
    }
}

void SCEPClientDlg::findPriKey()
{
    QString strPath = mPriKeyPathText->text();

    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 )
    {
        mPriKeyPathText->setText( filePath );
    }
}

void SCEPClientDlg::typeCACert()
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

void SCEPClientDlg::typeCert()
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

void SCEPClientDlg::typePriKey()
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

void SCEPClientDlg::viewCACert()
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

void SCEPClientDlg::viewCert()
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

void SCEPClientDlg::viewPriKey()
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

void SCEPClientDlg::decodeCACert()
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

void SCEPClientDlg::decodeCert()
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

void SCEPClientDlg::decodePriKey()
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

void SCEPClientDlg::decodeRequest()
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

    berApplet->decodeData( &binData, "SCEP Request" );

    JS_BIN_reset( &binData );
}

void SCEPClientDlg::decodeResponse()
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

    berApplet->decodeData( &binData, "SCEP Response" );

    JS_BIN_reset( &binData );
}

void SCEPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void SCEPClientDlg::clearResponse()
{
    mResponseText->clear();
}

void SCEPClientDlg::requestChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mRequestText->toPlainText() );
    mRequestLenText->setText( QString("%1").arg( strLen ) );
}

void SCEPClientDlg::responseChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mResponseText->toPlainText() );
    mResponseLenText->setText( QString("%1").arg( strLen ) );
}

void SCEPClientDlg::clickClearAll()
{
    mNonceText->clear();
    mTransIDText->clear();

    clearRequest();
    clearResponse();
}

void SCEPClientDlg::clickGetCA()
{
    int ret = 0;
    int nStatus = 0;

    BIN binCA = {0,0};
    QString strURL = mURLCombo->currentText();

    CertInfoDlg certInfo;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SCEP URL"), this );
        return;
    }

    strURL += "/pkiclient.exe?operation=GetCACert";

    ret = JS_HTTP_requestGetBin2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        &nStatus,
        &binCA );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP get [%1:%2]").arg(ret).arg(nStatus), this );
        goto end;
    }

    if( mCACertPathText->text().length() < 1 )
        mCACertPathText->setText( strURL );

    certInfo.setCertBIN( &binCA );
    certInfo.exec();

end :
    JS_BIN_reset( &binCA );
}

void SCEPClientDlg::clickMakeIssue()
{
    int ret = 0;
    int nStatus = -1;
    BIN binNonce = {0,0};
    BIN binCA = {0,0};
    BIN binNewPri = {0,0};
    BIN binNewCert = {0,0};
    BIN binCSR = {0,0};
    char *pTransID = NULL;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignedData = {0,0};

    QString strPriHex;
    QString strCSRHex;

    GenKeyPairDlg genKeyPair;
    MakeCSRDlg makeCSR;

    QString strURL = mURLCombo->currentText();
    QString strCAPath = mCACertPathText->text();
    QString strNonce = mNonceText->text();
    QString strTransID = mTransIDText->text();
    QString strLink;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SCEP URL"), this );
        mURLCombo->setFocus();
        return;
    }

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
            return;
        }
        else
        {
            mCACertPathText->setText( strCAPath );
        }
    }

    ret = getCA( &binCA );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA certificate" ), this );
        goto end;
    }

    genKeyPair.setFixName( tr("SCEP Issue KeyPair" ));
    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strPriHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binNewPri );

    makeCSR.setPriKey( &binNewPri );
    if( makeCSR.exec() != QDialog::Accepted ) goto end;

    strCSRHex = makeCSR.getCSRHex();
    JS_BIN_decodeHex( strCSRHex.toStdString().c_str(), &binCSR );

    if( strNonce.length() < 1 )
    {
        JS_PKI_genRandom( 16, &binNonce );
        mNonceText->setText( getHexString( &binNonce ));
    }
    else
    {
        JS_BIN_decodeHex( strNonce.toStdString().c_str(), &binNonce );
    }

    if( strTransID.length() < 1 )
    {
        JS_SCEP_makeTransID( &binCSR, &pTransID );
        mTransIDText->setText( pTransID );
    }
    else
    {
        pTransID = JS_strdup( strTransID.toStdString().c_str() );
    }

    ret = JS_SCEP_makePKIReq( &binCSR, &binNewPri, NULL, &binCA, &binNonce, pTransID, &binReq );
    if( ret == 0 )
    {
        mRequestText->setPlainText(getHexString(&binReq));
    }
    else
    {
        berApplet->warnLog( tr( "fail to make request: %1").arg(ret), this );
    }

    strLink = strURL;
    strLink += "/pkiclient.exe?operation=PKIOperation";

    ret = JS_HTTP_requestPostBin2(
        strLink.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-pki-message",
        &binReq,
        &nStatus,
        &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

    setUsedURL( strURL );

    mResponseText->setPlainText( getHexString( &binRsp ));


    ret = JS_SCEP_parseCertRsp(
        &binRsp,
        &binCA,
        &binNewPri,
        &binNonce,
        pTransID,
        &binSignedData );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( "failed to parse CertRsp" ), this );
        goto end;
    }

    ret = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNewCert );
    if( ret != 0 )
    {
        berApplet->warnLog( QString("failed to get sign certificate with SCEP [%1]").arg( ret ), this );
        goto end;
    }

    savePriKeyCert( &binNewPri, &binNewCert );

end :
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binNewPri );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSignedData );

    if( pTransID ) JS_free( pTransID );
}

void SCEPClientDlg::clickMakeUpdate()
{
    int ret = 0;
    int nStatus = -1;
    BIN binNonce = {0,0};
    BIN binCA = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binNewCert = {0,0};
    BIN binCSR = {0,0};
    char *pTransID = NULL;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignedData = {0,0};

    QString strCSRHex;

    MakeCSRDlg makeCSR;
    QString strCAPath = mCACertPathText->text();
    QString strCertPath = mCertPathText->text();
    QString strPriKeyPath = mPriKeyPathText->text();
    QString strNonce = mNonceText->text();
    QString strTransID = mTransIDText->text();

    QString strURL = mURLCombo->currentText();
    QString strLink;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SCEP URL"), this );
        mURLCombo->setFocus();
        return;
    }



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
            return;
        }
        else
        {
            mCACertPathText->setText( strCAPath );
        }
    }

    ret = getCA( &binCA );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA certificate" ), this );
        goto end;
    }

    if( mCertGroup->isChecked() == true )
    {
        if( strCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a certificate" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
    }

    makeCSR.setPriKey( &binPri );
    if( makeCSR.exec() != QDialog::Accepted ) goto end;

    strCSRHex = makeCSR.getCSRHex();
    JS_BIN_decodeHex( strCSRHex.toStdString().c_str(), &binCSR );

    if( strNonce.length() < 1 )
    {
        JS_PKI_genRandom( 16, &binNonce );
        mNonceText->setText( getHexString( &binNonce ));
    }
    else
    {
        JS_BIN_decodeHex( strNonce.toStdString().c_str(), &binNonce );
    }

    if( strTransID.length() < 1 )
    {
        JS_SCEP_makeTransID( &binCSR, &pTransID );
        mTransIDText->setText( pTransID );
    }
    else
    {
        pTransID = JS_strdup( strTransID.toStdString().c_str() );
    }

    ret = JS_SCEP_makePKIReq( &binCSR, &binPri, &binCert, &binCA, &binNonce, pTransID, &binReq );
    if( ret == 0 )
    {
        mRequestText->setPlainText(getHexString(&binReq));
    }
    else
    {
        berApplet->warnLog( tr( "fail to make request: %1").arg(ret), this );
    }

    strLink = strURL;
    strLink += "/pkiclient.exe?operation=PKIOperation";

    ret = JS_HTTP_requestPostBin2(
        strLink.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-pki-message",
        &binReq,
        &nStatus,
        &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

    setUsedURL( strURL );
    mResponseText->setPlainText( getHexString( &binRsp ));

    ret = JS_SCEP_parseCertRsp(
        &binRsp,
        &binCA,
        &binPri,
        &binNonce,
        pTransID,
        &binSignedData );

    if( ret != 0 )
    {
        berApplet->warnLog( QString("failed to parse CertRsp : %1").arg(ret), this );
        goto end;
    }

    ret = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNewCert );
    if( ret != 0 )
    {
        berApplet->warnLog( QString("failed to get sign certificate in reply: %1").arg(ret), this );
        goto end;
    }

    savePriKeyCert( &binPri, &binNewCert );

end :
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSignedData );

    if( pTransID ) JS_free( pTransID );
}

void SCEPClientDlg::clickMakeGetCRL()
{
    int ret = 0;
    int nStatus = -1;
    BIN binNonce = {0,0};
    BIN binCA = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binCRL = {0,0};
    BIN binSignedData = {0,0};

    QString strCAPath = mCACertPathText->text();
    QString strCertPath = mCertPathText->text();
    QString strPriKeyPath = mPriKeyPathText->text();
    QString strNonce = mNonceText->text();
    QString strTransID = mTransIDText->text();

    char *pTransID = NULL;

    QString strURL = mURLCombo->currentText();
    QString strLink;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SCEP URL"), this );
        return;
    }



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
            return;
        }
        else
        {
            mCACertPathText->setText( strCAPath );
        }
    }

    ret = getCA( &binCA );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA certificate" ), this );
        goto end;
    }

    if( mCertGroup->isChecked() == true )
    {
        if( strCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a certificate" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binCert );
        certMan.getPriKey( &binPri );
    }


    if( strNonce.length() < 1 )
    {
        JS_PKI_genRandom( 16, &binNonce );
        mNonceText->setText( getHexString( &binNonce ));
    }
    else
    {
        JS_BIN_decodeHex( strNonce.toStdString().c_str(), &binNonce );
    }

    if( strTransID.length() < 1 )
    {
        pTransID = JS_strdup( "12345678" );
        mTransIDText->setText( pTransID );
    }
    else
    {
        pTransID = JS_strdup( strTransID.toStdString().c_str() );
    }


    ret = JS_SCEP_makeGetCRL( &binCert, &binPri, &binCert, &binCA, &binNonce, pTransID, &binReq );
    if( ret == 0 )
    {
        mRequestText->setPlainText(getHexString(&binReq));
    }
    else
    {
        berApplet->warnLog( tr( "fail to make to get crl: %1").arg(ret), this );
    }

    strLink = strURL;
    strLink += "/pkiclient.exe?operation=PKIOperation";

    ret = JS_HTTP_requestPostBin2(
        strLink.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-pki-message",
        &binReq,
        &nStatus,
        &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

    setUsedURL( strURL );
    mResponseText->setPlainText( getHexString( &binRsp ));

    ret = JS_SCEP_parseCertRsp(
        &binRsp,
        &binCA,
        &binPri,
        &binNonce,
        pTransID,
        &binSignedData );

    if( ret != 0 )
    {
        berApplet->warnLog( QString("failed to parse CertRsp : %1").arg(ret), this );
        goto end;
    }

    ret = JS_SCEP_getCRL( &binSignedData, &binCRL );
    if( ret != 0 )
    {
        berApplet->warningBox( QString("failed to get CRL with SCEP: %1").arg(ret), this );
        goto end;
    }

    berApplet->log( QString( "CRL: %1").arg( getHexString( &binCRL )));

end :
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binSignedData );

    if( pTransID ) JS_free( pTransID );
}

void SCEPClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strReq = mRequestText->toPlainText();
    QString strLink;

    CertInfoDlg certInfo;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SCEP URL"), this );
        return;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        goto end;
    }

    getBINFromString( &binReq, DATA_HEX, strReq );

    strLink = strURL;
    strLink += "/pkiclient.exe?operation=PKIOperation";

    ret = JS_HTTP_requestPostBin2(
        strLink.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-pki-message",
        &binReq,
        &nStatus,
        &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

    mResponseText->setPlainText( getHexString( &binRsp ));
    setUsedURL( strURL );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void SCEPClientDlg::clickVerify()
{
    int ret = 0;

    BIN binRsp = {0,0};
    BIN binCA = {0,0};
    BIN binPriKey = {0,0};
    BIN binNonce = {0,0};

    BIN binData = {0,0};

    QString strRsp = mResponseText->toPlainText();
    QString strPriPath = mPriKeyPathText->text();
    QString strNonce = mNonceText->text();
    QString strTransID = mTransIDText->text();

    if( strRsp.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        mResponseText->setFocus();
        goto end;
    }

    if( mCertGroup->isChecked() == true )
    {
        ret = readPrivateKey( &binPriKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPriKey );
    }

    getBINFromString( &binRsp, DATA_HEX, strRsp );
    getBINFromString( &binNonce, DATA_HEX, strNonce );


    ret = getCA( &binCA );
    if( ret != 0 ) goto end;

    ret = JS_SCEP_parseCertRsp(
        &binRsp,
        &binCA,
        &binPriKey,
        &binNonce,
        strTransID.toStdString().c_str(),
        &binData );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( "failed to verify Rsp" ), this );
    }
    else
    {
        berApplet->messageLog( QString( "Verify OK" ), this );
        berApplet->log( QString( "SignedData: %1").arg( getHexString(&binData)));
    }


end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binData );
}

void SCEPClientDlg::changeNonce( const QString text )
{
    int len = text.length() / 2;
    mNonceLenText->setText( QString("%1").arg( len ));
}

void SCEPClientDlg::changeTransID( const QString text )
{
    int len = text.length();
    mTransIDLenText->setText( QString("%1").arg( len ));
}
