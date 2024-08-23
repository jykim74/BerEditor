#include <QSettings>

#include "ocsp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_error.h"

const QString kOCSPUsedURL = "OCSPUsedURL";

OCSPClientDlg::OCSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);


    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mUseSignCheck, SIGNAL(clicked()), this, SLOT(checkUseSign()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));

    connect( mOCSPClearBtn, SIGNAL(clicked()), this, SLOT(clickClearOCSP()));
    connect( mSetURLBtn, SIGNAL(clicked()), this, SLOT(clickSetURL()));
    connect( mSetCACertBtn, SIGNAL(clicked()), this, SLOT(clickSetCACert()));

    connect( mFindCACertBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindSignCertBtn, SIGNAL(clicked()), this, SLOT(findSignCert()));
    connect( mFindSignPriKeyBtn, SIGNAL(clicked()), this, SLOT(findSignPriKey()));
    connect( mFindSrvCertBtn, SIGNAL(clicked()), this, SLOT(findSrvCert()));

    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));
    connect( mSignCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignCert()));
    connect( mSignPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignPriKey()));
    connect( mSignPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(viewSignPriKey()));
    connect( mSrvCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSrvCert()));

    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mSignCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSignCert()));
    connect( mSrvCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSrvCert()));

    connect( mCACertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mSignCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSignCert()));
    connect( mSignPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSignPriKey()));
    connect( mSrvCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSrvCert()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mEncSignPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);


    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mSignCertViewBtn->setFixedWidth(34);
    mSignCertDecodeBtn->setFixedWidth(34);
    mSignCertTypeBtn->setFixedWidth(34);
    mSignPriKeyDecodeBtn->setFixedWidth(34);
    mSignPriKeyTypeBtn->setFixedWidth(34);
    mSignPriKeyViewBtn->setFixedWidth(34);
    mSrvCertViewBtn->setFixedWidth(34);
    mSrvCertDecodeBtn->setFixedWidth(34);
    mSrvCertTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);

    mCertGroup->layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
    mEncodeBtn->setDefault(true);
}

OCSPClientDlg::~OCSPClientDlg()
{

}

void OCSPClientDlg::checkEncPriKey()
{
    bool bVal = mEncSignPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void OCSPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    checkUseSign();
    checkEncPriKey();
}

QStringList OCSPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kOCSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void OCSPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    for( int i = 0; i < mURLCombo->count(); i++ )
    {
        QString strPosURL = mURLCombo->itemText(i);
        if( strURL == strPosURL ) return;
    }

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kOCSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kOCSPUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }
}

void OCSPClientDlg::checkUseSign()
{
    if( mUseSignCheck->isChecked() )
        mCertGroup->setEnabled( true );
    else
        mCertGroup->setEnabled( false );
}

void OCSPClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kOCSPUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void OCSPClientDlg::clickClearOCSP()
{
    mURLCombo->setCurrentText("");
    mCACertPathText->clear();
    mCertPathText->clear();
}

void OCSPClientDlg::clickSetURL()
{
    int ret = 0;
    BIN binData = {0,0};
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtList = NULL;

    QString strAIAExt;
    QString strURL;
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    ret = JS_PKI_getCertInfo( &binData, &sCertInfo, &pExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "invalid certificate: %1").arg(ret), this );
        goto end;
    }

    strAIAExt = CertInfoDlg::getValueFromExtList( kExtNameAIA, pExtList );
    if( strAIAExt.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no AIA" ), this );
        goto end;
    }

    strURL = CertInfoDlg::getOCSP_URIFromExt( strAIAExt );
    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no OCSP URL" ), this );
        goto end;
    }

    mURLCombo->setCurrentText( strURL );

end :
    JS_BIN_reset( &binData );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );
}

void OCSPClientDlg::clickSetCACert()
{
    int ret = 0;
    BIN binData = {0,0};
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtList = NULL;
    QString strAIAExt;
    QString strCAPath;
    QString strFile = mCertPathText->text();


    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    ret = JS_PKI_getCertInfo( &binData, &sCertInfo, &pExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "invalid certificate: %1").arg(ret), this );
        goto end;
    }

    strAIAExt = CertInfoDlg::getValueFromExtList( kExtNameAIA, pExtList );
    if( strAIAExt.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no AIA" ), this );
        goto end;
    }

    strCAPath = CertInfoDlg::getCA_URIFromExt( strAIAExt );
    if( strCAPath.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no CA Path" ), this );
        goto end;
    }

    mCACertPathText->setText( strCAPath );

end :
    JS_BIN_reset( &binData );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );
}

int OCSPClientDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mSignPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mSignPriKeyPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        mSignPriKeyPathText->setFocus();
        return  -1;
    }

    if( mEncSignPriKeyCheck->isChecked() )
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

void OCSPClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCACertPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void OCSPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mCertPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void OCSPClientDlg::findSignCert()
{
    QString strPath = mSignCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mSignCertPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void OCSPClientDlg::findSignPriKey()
{
    QString strPath = mSignPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 )
    {
        mSignPriKeyPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void OCSPClientDlg::findSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mSrvCertPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void OCSPClientDlg::typeCACert()
{
    int ret = 0;
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

//    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    ret = getDataFromURI( strFile, &binData );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA"), this );
        goto end;
    }

    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void OCSPClientDlg::typeCert()
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
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void OCSPClientDlg::typeSignCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        mSignCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void OCSPClientDlg::typeSignPriKey()
{
    int nType = -1;
    BIN binPri = {0,0};

    int ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nType = JS_PKI_getPriKeyType( &binPri );
    berApplet->messageBox( tr( "The private key type is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void OCSPClientDlg::typeSrvCert()
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

void OCSPClientDlg::viewCACert()
{
    int ret = 0;
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

//    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    ret = getDataFromURI( strFile, &binData );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA"), this );
        goto end;
    }

    certInfo.setCertBIN( &binData );
    certInfo.exec();

end :
    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewSignCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        mSignCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewSignPriKey()
{
    BIN binPri = {0,0};
    PriKeyInfoDlg priKeyInfo;

    int ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void OCSPClientDlg::viewSrvCert()
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

void OCSPClientDlg::decodeCACert()
{
    int ret = 0;
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        mCACertPathText->setFocus();
        return;
    }

//    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    ret = getDataFromURI( strFile, &binData );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA"), this );
        goto end;
    }

    berApplet->decodeData( &binData, strFile );
end :
    JS_BIN_reset( &binData );
}


void OCSPClientDlg::decodeCert()
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

void OCSPClientDlg::decodeSignCert()
{
    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        mSignCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeSignPriKey()
{
    BIN binData = {0,0};
    QString strFile = mSignPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign private key" ), this );
        mSignPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeSrvCert()
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

void OCSPClientDlg::decodeRequest()
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

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeResponse()
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

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}


void OCSPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void OCSPClientDlg::clearResponse()
{
    mResponseText->clear();
}


void OCSPClientDlg::clickEncode()
{
    int ret = 0;

    BIN binCA = {0,0};
    BIN binCert = {0,0};
    BIN binSignCert = {0,0};
    BIN binSignPriKey = {0,0};

    BIN binReq = {0,0};

    QString strHash = mHashCombo->currentText();
    QString strCAPath = mCACertPathText->text();
    QString strCertPath = mCertPathText->text();

    if( strCAPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCA);
        certMan.setTitle( tr( "Select CA certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

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

    if( strCertPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select target certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strCertPath = certMan.getSeletedCertPath();

        if( strCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a certificate" ), this );
            return;
        }
        else
        {
            mCertPathText->setText( strCertPath );
        }
    }

    if( mUseSignCheck->isChecked() )
    {
        if( mCertGroup->isChecked() )
        {
            QString strSignCertPath = mSignCertPathText->text();

            if( strSignCertPath.length() < 1 )
            {
                berApplet->warningBox( tr( "Find a sign certificate" ), this );
                mSignCertPathText->setFocus();
                return;
            }

            JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binSignCert );
            ret = readPrivateKey( &binSignPriKey );
            if( ret != 0 ) goto end;
        }
        else
        {
            CertManDlg certMan;
            QString strPriHex;
            QString strCertHex;

            certMan.setMode( ManModeSelBoth );
            certMan.setTitle( tr( "Select a certificate") );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            strPriHex = certMan.getPriKeyHex();
            strCertHex = certMan.getCertHex();

            JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binSignPriKey );
            JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binSignCert );
        }
    }

//    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );
    ret = getDataFromURI( strCAPath, &binCA );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get CA"), this );
        goto end;
    }

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( mUseSignCheck->isChecked() )
        ret = JS_OCSP_encodeRequest( &binCert, &binCA, strHash.toStdString().c_str(), &binSignPriKey, &binSignCert, &binReq );
    else
        ret = JS_OCSP_encodeRequest( &binCert, &binCA, strHash.toStdString().c_str(), NULL, NULL, &binReq );

    if( ret == 0 )
    {
        mRequestText->setPlainText( getHexString( &binReq ));
    }
    else
    {
        berApplet->warnLog( tr( "fail to encode request: %1").arg(ret), this );
    }

end :
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binSignPriKey );
    JS_BIN_reset( &binReq );
}

void OCSPClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strURL = mURLCombo->currentText();

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert OCSP URL"), this );
        mURLCombo->setFocus();
        goto end;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        mRequestText->setFocus();
        goto end;
    }

    getBINFromString( &binReq, DATA_HEX, strReq );

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/ocsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to request : %d\n", ret );
        goto end;
    }

    if( ret == 0 )
    {
        mResponseText->setPlainText( getHexString( &binRsp ));
        setUsedURL( strURL );
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to OCSP server: %1").arg( ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void OCSPClientDlg::clickVerify()
{
    int ret = 0;
    BIN binSrvCert = {0,0};
    BIN binRsp = {0,0};

    QString strSrvCertPath = mSrvCertPathText->text();
    QString strRspHex = mResponseText->toPlainText();


    JCertIDInfo sIDInfo;
    JCertStatusInfo sStatusInfo;

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    if( strSrvCertPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select OCSP server certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strSrvCertPath = certMan.getSeletedCertPath();
        if( strSrvCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a OCSP server certificate"), this );
            goto end;
        }
        else
        {
            mSrvCertPathText->setText( strSrvCertPath );
        }
    }

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );
    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_OCSP_decodeResponse( &binRsp, &binSrvCert, &sIDInfo, &sStatusInfo );

    if( ret == JSR_INVALID )
    {
        berApplet->warningBox( tr( "OCSP Verify fail [status: %1(%2)]" )
                                  .arg( JS_OCSP_getCertStatusName( sStatusInfo.nStatus ) )
                                  .arg( sStatusInfo.nStatus ), this);
    }
    else if( ret == JSR_VERIFY)
    {
        berApplet->messageBox( tr( "OCSP Verify OK [status: %1(%2)]" )
                                  .arg( JS_OCSP_getCertStatusName( sStatusInfo.nStatus ) )
                                  .arg( sStatusInfo.nStatus ), this);
    }
    else
    {
        berApplet->warningBox( tr( "failed to decode response: %1").arg( ret ));
    }

end :
    JS_BIN_reset( &binSrvCert );
    JS_BIN_reset( &binRsp );
    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
}

void OCSPClientDlg::requestChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mRequestText->toPlainText() );
    mRequestLenText->setText( QString("%1").arg( strLen ) );
}

void OCSPClientDlg::responseChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mResponseText->toPlainText() );
    mResponseLenText->setText( QString("%1").arg( strLen ) );
}
