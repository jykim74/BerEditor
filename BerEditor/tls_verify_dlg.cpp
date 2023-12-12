#include <QUrl>

#include "common.h"
#include "tls_verify_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_ssl.h"

TLSVerifyDlg::TLSVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
}

TLSVerifyDlg::~TLSVerifyDlg()
{

}

void TLSVerifyDlg::initialize()
{
    QStringList sURLLabels = { tr( "URL" ), tr( "From" ), tr( "To" ), tr( "Days Left") };

    mURLTable->clear();
    mURLTable->horizontalHeader()->setStretchLastSection(true);
    mURLTable->setColumnCount( sURLLabels.size() );
    mURLTable->setHorizontalHeaderLabels( sURLLabels );
    mURLTable->verticalHeader()->setVisible(false);
    mURLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mURLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mURLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mURLCombo->setEditable( true );
}

int TLSVerifyDlg::verifyURL( const QString strHost, int nPort )
{
    int ret = 0;
    int count = 0;
    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;
    BINList *pCertList = NULL;

    JS_SSL_initClient( &pCTX );

    ret = JS_SSL_connect( pCTX, strHost.toStdString().c_str(), nPort, &pSSL );

    if( ret != 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    ret = JS_SSL_getChains( pSSL, &pCertList );
//    ret = JS_SSL_getChains2( pCTX, &pCertList );

    count = JS_BIN_countList( pCertList );
    berApplet->log( QString( "Chain Count: %1").arg( count ) );

end :
    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pCertList ) JS_BIN_resetList( &pCertList );

    return ret;
}

void TLSVerifyDlg::clickConnect()
{
    QString strHost;
    int nPort = 443;
    QUrl url;

    QString strURL = mURLCombo->currentText();

    url.setUrl( strURL );

    if( url.isValid() == false )
    {
        berApplet->warningBox( tr( "Invalid URL: %1").arg( strURL ), this );
        return;
    }

    nPort = url.port( 443 );
    strHost = url.host();

    berApplet->log( QString( "Host:Port => %1:%2" ).arg( strHost ).arg( nPort ) );

    verifyURL( strHost, nPort );
}

void TLSVerifyDlg::clickRefresh()
{

}
