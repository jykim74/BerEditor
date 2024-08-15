#include <QFileDialog>
#include <QUrl>
#include <QSettings>

#include "ttlv_client_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "cert_man_dlg.h"
#include "cert_info_dlg.h"
#include "pri_key_info_dlg.h"

#include "js_kms.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_pki.h"

const QString kKMIPUsedURL = "KMIPUsedURL";

TTLVClientDlg::TTLVClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mFindCABtn, SIGNAL(clicked()), this, SLOT(findCA()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));

    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));

    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));

    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCACertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));

    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(viewPriKey()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));

    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));
    connect( mReadMainBtn, SIGNAL(clicked()), this, SLOT(clickReadMain()));

    initialize();
    mSendBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);

    mPriKeyDecodeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TTLVClientDlg::~TTLVClientDlg()
{

}

void TTLVClientDlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void TTLVClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kKMIPUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

QStringList TTLVClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kKMIPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void TTLVClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kKMIPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kKMIPUsedURL, list );
    settings.endGroup();
}


void TTLVClientDlg::initialize()
{
    mURLCombo->setEditable(true);

    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }

    checkEncPriKey();
}

void TTLVClientDlg::findCA()
{
    QString strPath = QDir::currentPath();
    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.isEmpty() ) return;

    mCACertPathText->setText( filePath );
}

void TTLVClientDlg::findCert()
{
    QString strPath = QDir::currentPath();
    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.isEmpty() ) return;

    mClientCertPathText->setText( filePath );
}

void TTLVClientDlg::findPriKey()
{
    QString strPath = QDir::currentPath();
    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.isEmpty() ) return;

    mClientPriKeyPathText->setText( filePath );
}

int TTLVClientDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mClientPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mClientPriKeyPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        mClientPriKeyPathText->setFocus();
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

void TTLVClientDlg::clickSend()
{
    int ret = 0;

    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;

    BIN binCA = {0,0};
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};
    BIN binResponse = {0,0};
    char *pHex = NULL;

    int nSockFd = -1;
    BIN binTTLV = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strRequest = mRequestText->toPlainText();

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert KMIP URL"), this );
        mURLCombo->setFocus();
        return;
    }

    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no request" ), this );
        mRequestText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strRequest.toStdString().c_str(), &binTTLV );

    QString strCACertPath = mCACertPathText->text();
    QString strCertPath = mClientCertPathText->text();
    QString strPriKeyPath = mClientPriKeyPathText->text();
    QString strHost;
    int nPort;

    QUrl url;
    url.setUrl( strURL );

    strHost = url.host();
    nPort = url.port(443);

    if( strCACertPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCA);
        certMan.setTitle( tr( "Select CA certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strCACertPath = certMan.getSeletedCAPath();
        if( strCACertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a CA certificate" ), this );
            return;
        }
        else
        {
            mCACertPathText->setText( strCACertPath );
        }
    }

    JS_BIN_fileRead( strCACertPath.toStdString().c_str(), &binCA );

    if( mCertGroup->isChecked() )
    {
        if( strCertPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a certificate" ), this );
            mClientCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
        ret = readPrivateKey( &binPriKey );
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

        JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binPriKey );
        JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binCert );
    }

    nSockFd = JS_NET_connect( strHost.toStdString().c_str(), nPort );
    if( nSockFd < 0 )
    {
        goto end;
    }

    JS_SSL_initClient( &pCTX );
    JS_SSL_initSSL( pCTX, nSockFd, &pSSL );
    JS_SSL_setClientCACert( pCTX, &binCA );
    JS_SSL_setCertAndPriKey( pCTX, &binPriKey, &binCert );

    JS_SSL_connect( pSSL );
    if( pSSL == NULL )
    {
        goto end;
    }

    ret = JS_KMS_sendSSL( pSSL, &binTTLV );

    ret = JS_KMS_receiveSSL( pSSL, &binResponse );
    JS_BIN_encodeHex( &binResponse, &pHex );

    if( pHex )
    {
        mResponseText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );
    }

    setUsedURL( strURL );

end :
    JS_BIN_reset( &binTTLV );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binResponse );

    JS_SSL_clear( pSSL );
    JS_SSL_finish( &pCTX );
}

void TTLVClientDlg::close()
{
    QDialog::reject();
}

void TTLVClientDlg::changeRequest()
{
    QString strLen = getDataLenString( DATA_HEX, mRequestText->toPlainText() );
    mRequestLenText->setText( QString("%1").arg( strLen ));
}

void TTLVClientDlg::changeResponse()
{
    QString strLen = getDataLenString( DATA_HEX, mResponseText->toPlainText() );
    mResponseLenText->setText( QString("%1").arg( strLen ));
}

void TTLVClientDlg::typeCACert()
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

void TTLVClientDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mClientCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mClientCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void TTLVClientDlg::typePriKey()
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

void TTLVClientDlg::viewCACert()
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

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::viewCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mClientCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mClientCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::viewPriKey()
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


void TTLVClientDlg::decodeCACert()
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

void TTLVClientDlg::decodeCert()
{
    BIN binData = {0,0};
    QString strFile = mClientCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mClientCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::decodePriKey()
{
    BIN binData = {0,0};
    QString strFile = mClientPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a private key" ), this );
        mClientPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::decodeRequest()
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

    berApplet->decodeTTLV( &binData );

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::decodeResponse()
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

    berApplet->decodeTTLV( &binData );

    JS_BIN_reset( &binData );
}

void TTLVClientDlg::clearRequest()
{
    mRequestText->clear();
}

void TTLVClientDlg::clearResponse()
{
    mResponseText->clear();
}

void TTLVClientDlg::clickReadMain()
{
    BIN binTTLV = berApplet->getTTLV();
    if( binTTLV.nLen <= 0 || berApplet->mainWindow()->isTTLV() == false )
    {
        berApplet->warningBox( tr( "There is no TTLV data" ), this );
        return;
    }

    mRequestText->setPlainText( getHexString( &binTTLV ));
}
