#include <QUrl>
#include <QDateTime>
#include <QSettings>
#include <QMenu>

#include "common.h"
#include "tls_verify_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_util.h"
#include "cert_info_dlg.h"

const QString kTLSUsedURL = "TLSUsedURL";

TLSVerifyDlg::TLSVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    ssl_pctx_ = NULL;

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mClearSaveURLBtn, SIGNAL(clicked()), this, SLOT(clickClearSaveURL()));
    connect( mClearURLBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mLoadTrustBtn, SIGNAL(clicked()), this, SLOT(clickLoadTrust()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clickClearResult()));

    connect( mURLTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));
    connect( mURLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(viewCertTableMenu()));
    connect( mURLTable, SIGNAL(clicked(QModelIndex)), this, SLOT(selectTable(QModelIndex)));
    connect( mURLTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));

    connect( mTrustFolderFindBtn, SIGNAL(clicked()), this, SLOT(findTrustFolder()));
    connect( mTrustCACertFindBtn, SIGNAL(clicked()), this, SLOT(findTrustCACert()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

TLSVerifyDlg::~TLSVerifyDlg()
{
    if( ssl_pctx_ ) JS_SSL_finish( (SSL_CTX **)&ssl_pctx_ );
}

void TLSVerifyDlg::log( const QString strLog, QColor cr )
{
    QTextCursor cursor = mLogText->textCursor();
    //    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.insertText( "\n" );

    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}

void TLSVerifyDlg::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

void TLSVerifyDlg::initialize()
{
    QStringList sURLLabels = { tr( "URL" ), tr( "Port" ), tr( "From" ), tr( "To" ), tr( "Left") };

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

    mURLTree->clear();
    mURLTree->header()->setVisible(false);
    mURLTree->setColumnCount(1);

    JS_SSL_initClient( (SSL_CTX **)&ssl_pctx_ );
    JStrList *pCipherList = NULL;
    JS_SSL_getCiphersList( (SSL_CTX *)ssl_pctx_, &pCipherList );
    JStrList *pCurList = pCipherList;

    while( pCurList )
    {
        mCipherListCombo->addItem( pCurList->pStr );
        pCurList = pCurList->pNext;
    }

    if( pCipherList ) JS_UTIL_resetStrList( &pCipherList );

    tabWidget->setCurrentIndex(0);
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
    long uFlags = getFlags();

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( mFixCipherNameCheck->isChecked() )
    {
        QString strCipher = mCipherListCombo->currentText();

        JS_SSL_setCiphersList( (SSL_CTX *)ssl_pctx_, strCipher.toStdString().c_str() );
    }

    JS_SSL_setFlags( (SSL_CTX *)ssl_pctx_, uFlags );

    log( QString( "SSL Host:Port       : %1:%2" ).arg( strHost ).arg( nPort ));

    int nSockFd = JS_NET_connect( strHost.toStdString().c_str(), nPort );
    if( nSockFd < 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    ret = JS_SSL_initSSL( (SSL_CTX *)ssl_pctx_, nSockFd, &pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString("fail to init SSL(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    if( mHostNameCheck->isChecked() ) JS_SSL_setHostName( pSSL, strHost.toStdString().c_str() );

    ret = JS_SSL_connect( pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to connect SSL:%1").arg( ret ));
        goto end;
    }

    log( QString( "Current TLS Version : %1").arg( JS_SSL_getCurrentVersionName( pSSL )));
    log( QString( "Current Cipher Name : %1").arg( JS_SSL_getCurrentCipherName( pSSL ) ));

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

//    pAtList = JS_BIN_getListAt( count - 1, pCertList );
//    JS_SSL_addCACert( pSSL, &pAtList->Bin );

    ret = JS_SSL_verifyCert( pSSL );
    log( QString( "Verify Certificate  : %1(%2)").arg( X509_verify_cert_error_string(ret)).arg( ret ));

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

long TLSVerifyDlg::getFlags()
{
    long uFlags = 0;

    if( mNoSSL2Check->isChecked() )
        uFlags |= SSL_OP_NO_SSLv2;

    if( mNoSSL3Check->isCheckable() )
        uFlags |= SSL_OP_NO_SSLv3;

    if( mNoCompCheck->isChecked() )
        uFlags |= SSL_OP_NO_COMPRESSION;

    if( mNoTicketCheck->isChecked() )
        uFlags |= SSL_OP_NO_TICKET;

    if( mNoTLS1Check->isChecked() )
        uFlags |= SSL_OP_NO_TLSv1;

    if( mNoTLS11Check->isChecked() )
        uFlags |= SSL_OP_NO_TLSv1_1;

    if( mNoTLS12Check->isChecked() )
        uFlags |= SSL_OP_NO_TLSv1_2;

    if( mNoTLS13Check->isChecked() )
        uFlags |= SSL_OP_NO_TLSv1_3;

    return uFlags;
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
    int nCount = mURLTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        mURLTable->removeRow(0);
    }
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

void TLSVerifyDlg::clickClearResult()
{
    mURLTree->clear();
    mLogText->clear();
}

void TLSVerifyDlg::findTrustFolder()
{
    QString strPath = mTrustFolderText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mTrustFolderText->setText( fileName );
}

void TLSVerifyDlg::findTrustCACert()
{
    QString strPath = mTrustCACertText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mTrustCACertText->setText( fileName );
}

void TLSVerifyDlg::clickLoadTrust()
{
    int ret = 0;
    QString strTrustFolder = mTrustFolderText->text();
    QString strTrustCACert = mTrustCACertText->text();

    if( strTrustFolder.length() < 1 && strTrustCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find Trust Folder or Trust CA Cert" ), this );
        return;
    }

    ret = JS_SSL_setVerifyLoaction( (SSL_CTX *)ssl_pctx_, strTrustCACert.toStdString().c_str(), strTrustFolder.toStdString().c_str() );
    if( ret == 0 )
    {
        berApplet->log( "Trust list loaded successfully" );
    }
    else
    {
        berApplet->elog( "fail to load trust list" );
    }
}

void TLSVerifyDlg::selectTable(QModelIndex index)
{

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
