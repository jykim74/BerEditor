#include <QFileDialog>

#include "ttlv_client_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "cert_man_dlg.h"

#include "js_kms.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_pki.h"

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
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));

    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
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


void TTLVClientDlg::initialize()
{
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
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
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

    int nSockFd = -1;

    BIN TTLV = berApplet->mainWindow()->ttlvModel()->getTTLV();
    if( TTLV.nLen <= 0 ) return;

    QString strHost = mHostText->text();
    QString strPort = mPortText->text();
    QString strCACertPath = mCACertPathText->text();
    QString strCertPath = mClientCertPathText->text();
    QString strPriKeyPath = mClientPriKeyPathText->text();

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

    nSockFd = JS_NET_connect( strHost.toStdString().c_str(), strPort.toInt() );
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

void TTLVClientDlg::changeResponse()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ));
}
