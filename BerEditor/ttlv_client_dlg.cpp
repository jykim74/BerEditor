#include <QFileDialog>

#include "ttlv_client_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

#include "js_kms.h"
#include "js_net.h"
#include "js_ssl.h"

TTLVClientDlg::TTLVClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mFindCABtn, SIGNAL(clicked()), this, SLOT(findCA()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));

    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(send()));
    connect( mViewResponseBtn, SIGNAL(clicked()), this, SLOT(viewResponse()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    setDefaults();
}

TTLVClientDlg::~TTLVClientDlg()
{

}

void TTLVClientDlg::setDefaults()
{
    QString strHost;
    QString strPort;


    QString strCACert = "D:/jsca/ssl_root_cert.der";
    QString strClientCert = "D:/jsca/ssl_cert.der";
    QString strClientPriKey = "D:/jsca/ssl_pri.der";

//    QString strCACert = "/Users/jykim/work/certs/root_cert.der";
//    QString strClientCert = "/Users/jykim/work/certs/client_certificate_john_smith.der";
//    QString strClientPriKey = "/Users/jykim/work/certs/client_key_john_smith.der";

    mHostText->setText( strHost );
    mPortText->setText( strPort );
    mCACertPathText->setText( strCACert );
    mClientCertPathText->setText( strClientCert );
    mClientPriKeyPathText->setText( strClientPriKey );
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

void TTLVClientDlg::send()
{
    int ret = 0;

    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;

    BIN binCA = {0,0};
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};
    BIN binResponse = {0,0};
    char *pHex = NULL;

    BIN TTLV = berApplet->mainWindow()->ttlvModel()->getTTLV();
    if( TTLV.nLen <= 0 ) return;

    QString strHost = mHostText->text();
    QString strPort = mPortText->text();
    QString strCACertPath = mCACertPathText->text();
    QString strCertPath = mClientCertPathText->text();
    QString strPriKeyPath = mClientPriKeyPathText->text();

    JS_BIN_fileRead( strCACertPath.toStdString().c_str(), &binCA );
    JS_BIN_fileRead( strCertPath.toStdString().c_str(), &binCert );
    JS_BIN_fileRead( strPriKeyPath.toStdString().c_str(), &binPriKey );

    int nSockFd = JS_NET_connect( strHost.toStdString().c_str(), strPort.toInt() );
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

    ret = JS_KMS_send( pSSL, &TTLV );

    ret = JS_KMS_receive( pSSL, &binResponse );
    JS_BIN_encodeHex( &binResponse, &pHex );

    if( pHex )
    {
        mResponseText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );
    }
end :
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binResponse );

    JS_SSL_clear( pSSL );
    JS_SSL_finish( &pCTX );
}

void TTLVClientDlg::viewResponse()
{
    BIN binTTLV = {0,0};

    JS_BIN_decodeHex( mResponseText->toPlainText().toStdString().c_str(), &binTTLV );

    berApplet->decodeTTLV( &binTTLV );
    QDialog::accept();


    JS_BIN_reset( &binTTLV );
}

void TTLVClientDlg::close()
{
    QDialog::reject();
}
