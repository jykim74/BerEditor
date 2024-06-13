#include <QSettings>

#include "ocsp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_http.h"

const QString kOCSPUsedURL = "OCSPUsedURL";

OCSPClientDlg::OCSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mUseSignCheck, SIGNAL(clicked()), this, SLOT(checkUseSign()));

    connect( mFindCACertBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindSignCertBtn, SIGNAL(clicked()), this, SLOT(findSignCert()));
    connect( mFindSignPriKeyBtn, SIGNAL(clicked()), this, SLOT(findSignPriKey()));
    connect( mFindSrvCertBtn, SIGNAL(clicked()), this, SLOT(findSrvCert()));

    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));
    connect( mSignCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignCert()));
    connect( mSignPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignPriKey()));
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
    mSrvCertViewBtn->setFixedWidth(34);
    mSrvCertDecodeBtn->setFixedWidth(34);
    mSrvCertTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);

    mSignGroup->layout()->setSpacing(5);
#endif
    initialize();
}

OCSPClientDlg::~OCSPClientDlg()
{

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

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kOCSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kOCSPUsedURL, list );
    settings.endGroup();
}

void OCSPClientDlg::checkUseSign()
{
    if( mUseSignCheck->isChecked() )
        mSignGroup->setEnabled( true );
    else
        mSignGroup->setEnabled( false );
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
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncSignPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
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
    if( filePath.length() > 0 ) mCACertPathText->setText( filePath );
}

void OCSPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void OCSPClientDlg::findSignCert()
{
    QString strPath = mSignCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mSignCertPathText->setText( filePath );
}

void OCSPClientDlg::findSignPriKey()
{
    QString strPath = mSignPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mSignPriKeyPathText->setText( filePath );
}

void OCSPClientDlg::findSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mSrvCertPathText->setText( filePath );
}

void OCSPClientDlg::typeCACert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeSignCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeSignPriKey()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mSignPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The private key type is %1").arg( getKeyTypeName( nType )), this);

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeSrvCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewCACert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

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
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewSrvCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeCACert()
{
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}


void OCSPClientDlg::decodeCert()
{
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
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
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();
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

    if( strCAPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    QString strCertPath = mCertPathText->text();

    if( strCertPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    if( mUseSignCheck->isChecked() )
    {
        QString strSignCertPath = mSignCertPathText->text();

        if( strSignCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a sign certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binSignCert );

        ret = readPrivateKey( &binSignPriKey );
        if( ret != 0 ) goto end;
    }

    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );
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
        goto end;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
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
        mResponseText->setPlainText( getHexString( &binRsp ));
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

}

void OCSPClientDlg::requestChanged()
{
    int nLen = mRequestText->toPlainText().length() / 2;
    mRequestLenText->setText( QString("%1").arg( nLen ) );
}

void OCSPClientDlg::responseChanged()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ) );
}
