#include <QUrl>
#include <QDateTime>

#include "common.h"
#include "tls_verify_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_ssl.h"
#include "js_util.h"

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

    mURLTable->setColumnWidth( 0, 240 );
    mURLTable->setColumnWidth( 1, 80 );
    mURLTable->setColumnWidth( 2, 80 );

    mURLCombo->setEditable( true );

    /*
    QFile qss(":/bereditor.qss");
    qss.open( QFile::ReadOnly );
    mURLTree->setStyleSheet(qss.readAll());
    qss.close();
    */

    mURLTree->clear();
    mURLTree->header()->setVisible(false);
    mURLTree->setColumnCount(1);
}

int TLSVerifyDlg::verifyURL( const QString strHost, int nPort )
{
    int ret = 0;
    int count = 0;
    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;
    BINList *pCertList = NULL;
    const BINList *pAtList = NULL;
    JCertInfo sCertInfo;
    char    sNotBefore[64];
    char    sNotAfter[64];

    int row = mURLTable->rowCount();
    time_t now_t = time( NULL );
    time_t left_t = 0;
    QString strLeft;
    QTableWidgetItem *item = new QTableWidgetItem( strHost );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_SSL_initClient( &pCTX );

    ret = JS_SSL_connect( pCTX, strHost.toStdString().c_str(), nPort, &pSSL );

    if( ret != 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    ret = JS_SSL_getChains( pSSL, &pCertList );
    count = JS_BIN_countList( pCertList );
    berApplet->log( QString( "Chain Count: %1").arg( count ) );

    pAtList = JS_BIN_getListAt( 0, pCertList );
    ret = JS_PKI_getCertInfo( &pAtList->Bin, &sCertInfo, NULL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "Invalid certificate data: %1").arg( ret ));
        goto end;
    }

    JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
    JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );
    left_t = ( sCertInfo.uNotAfter - now_t );

    if( left_t > 0 )
    {
        strLeft = QString( "%1 Days" ).arg( left_t / 86400 );
        item->setIcon(QIcon(":/images/cert.png"));
    }
    else
    {
        strLeft = "Expired";
        item->setIcon(QIcon(":/image/cert_revoked.png"));
    }

    mURLTable->insertRow( row );
    mURLTable->setRowHeight( row, 10 );
    mURLTable->setItem( row, 0, item );
    mURLTable->setItem( row, 1, new QTableWidgetItem( sNotBefore ));
    mURLTable->setItem( row, 2, new QTableWidgetItem( sNotAfter ));
    mURLTable->setItem( row, 3, new QTableWidgetItem( strLeft ));

    createTree( pCertList );

end :
    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pCertList ) JS_BIN_resetList( &pCertList );
    JS_PKI_resetCertInfo( &sCertInfo );

    return ret;
}

void TLSVerifyDlg::createTree( const BINList *pCertList )
{
    int ret = 0;
    int nCount = 0;
    const BINList *pAtList = NULL;
    JCertInfo sCertInfo;
    QTreeWidgetItem *last = NULL;

    mURLTree->clear();

    if( pCertList == NULL ) return;

    nCount = JS_BIN_countList( pCertList );

    for( int i = 0; i < nCount; i++ )
    {
        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        pAtList = JS_BIN_getListAt( (nCount - i - 1), pCertList );

        ret = JS_PKI_getCertInfo( &pAtList->Bin, &sCertInfo, NULL );

        QTreeWidgetItem *item = new QTreeWidgetItem;
        item->setText( 0, sCertInfo.pSubjectName );

        if( i == 0 )
        {
            mURLTree->insertTopLevelItem( 0, item );
            last = item;
        }
        else
        {
            last->addChild( item );
            last = item;
        }

        JS_PKI_resetCertInfo( &sCertInfo );
    }

    mURLTree->expandAll();
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

void TLSVerifyDlg::clickClearURL()
{

}

void TLSVerifyDlg::clickClearSaveURL()
{

}
