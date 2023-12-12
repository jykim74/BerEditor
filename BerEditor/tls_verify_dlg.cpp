#include <QUrl>
#include <QDateTime>
#include <QSettings>
#include <QMenu>

#include "common.h"
#include "tls_verify_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_ssl.h"
#include "js_util.h"
#include "cert_info_dlg.h"

const QString kTLSUsedURL = "TLSUsedURL";

TLSVerifyDlg::TLSVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mURLTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));
    connect( mURLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(viewCertTableMenu()));
    connect( mURLTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

TLSVerifyDlg::~TLSVerifyDlg()
{

}

void TLSVerifyDlg::initialize()
{
    QStringList sURLLabels = { tr( "URL" ), tr( "Port" ), tr( "From" ), tr( "To" ), tr( "Days Left") };

    mURLTable->clear();
    mURLTable->horizontalHeader()->setStretchLastSection(true);
    mURLTable->setColumnCount( sURLLabels.size() );
    mURLTable->setHorizontalHeaderLabels( sURLLabels );
    mURLTable->verticalHeader()->setVisible(false);
    mURLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mURLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mURLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mURLTable->setColumnWidth( 0, 240 );
    mURLTable->setColumnWidth( 1, 60 );
    mURLTable->setColumnWidth( 2, 80 );
    mURLTable->setColumnWidth( 3, 80 );

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

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

QStringList TLSVerifyDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTLSUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void TLSVerifyDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTLSUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTLSUsedURL, list );
    settings.endGroup();
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

    item->setData( Qt::UserRole, getHexString( &pAtList->Bin ));

    mURLTable->insertRow( row );
    mURLTable->setRowHeight( row, 10 );
    mURLTable->setItem( row, 0, item );
    mURLTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nPort )));
    mURLTable->setItem( row, 2, new QTableWidgetItem( sNotBefore ));
    mURLTable->setItem( row, 3, new QTableWidgetItem( sNotAfter ));
    mURLTable->setItem( row, 4, new QTableWidgetItem( strLeft ));

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
        item->setData( 0, Qt::UserRole, getHexString( &pAtList->Bin ));
        item->setIcon( 0, QIcon(":/images/cert.png"));

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
    setUsedURL( strURL );
}

void TLSVerifyDlg::clickRefresh()
{

}

void TLSVerifyDlg::clickClearURL()
{

}

void TLSVerifyDlg::clickClearSaveURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTLSUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void TLSVerifyDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr( "Delete" ), this );
    QAction *viewAct = new QAction( tr("View Cert"), this );
    QAction *decodeAct = new QAction( tr( "Decode Cert"), this);

    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteTableMenu()));
    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCertTableMenu()));
    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeCertTableMenu()));

    menu->addAction( delAct );
    menu->addAction( viewAct );
    menu->addAction( decodeAct );

    menu->popup( mURLTable->viewport()->mapToGlobal(pos));
}

void TLSVerifyDlg::deleteTableMenu()
{
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);
    mURLTable->removeRow(idx.row());
}

void TLSVerifyDlg::viewCertTableMenu()
{
    BIN binCert = {0,0};

    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);

    if( item == NULL ) return;

    QString strData = item->data(Qt::UserRole).toString();
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    CertInfoDlg certInfo;
    certInfo.setCertBIN( &binCert );
    JS_BIN_reset( &binCert );
    certInfo.exec();
}

void TLSVerifyDlg::decodeCertTableMenu()
{
    BIN binCert = {0,0};
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);

    if( item == NULL ) return;

    QString strData = item->data(Qt::UserRole).toString();
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    berApplet->decodeData( &binCert, "" );
    JS_BIN_reset( &binCert );
}

void TLSVerifyDlg::slotTreeMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction *viewAct = new QAction( tr("View Cert"), this );
    QAction *decodeAct = new QAction( tr( "Decode Cert"), this);

    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCertTreeMenu()));
    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeCertTreeMenu()));

    menu->addAction( viewAct );
    menu->addAction( decodeAct );

    menu->popup( mURLTree->viewport()->mapToGlobal(pos));
}

void TLSVerifyDlg::viewCertTreeMenu()
{
    QTreeWidgetItem *item = mURLTree->currentItem();
    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();

    BIN binCert = {0,0};
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    CertInfoDlg certInfo;
    certInfo.setCertBIN( &binCert );
    JS_BIN_reset( &binCert );
    certInfo.exec();
}

void TLSVerifyDlg::decodeCertTreeMenu()
{
    QTreeWidgetItem *item = mURLTree->currentItem();

    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();
    BIN binCert = {0,0};

    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    berApplet->decodeData( &binCert, "" );
    JS_BIN_reset( &binCert );
}
