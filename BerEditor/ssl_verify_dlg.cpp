#include <QUrl>
#include <QDateTime>
#include <QSettings>
#include <QMenu>
#include <QDir>
#include <QFile>

#include "common.h"
#include "ssl_verify_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_util.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include "js_pki.h"

const QString kTLSUsedURL = "TLSUsedURL";

void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;

    do
    {
        if (!name) break; /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (!(idx > -1))  break; /* failed */

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if (!entry) break; /* failed */

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (!data) break; /* failed */

        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (!utf8 || !(length > 0))  break; /* failed */

        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;

    } while (0);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;

    do
    {
        if (!cert) break; /* failed */

        names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
        if (!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if (!count) break; /* failed */

        for (i = 0; i < count; ++i)
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if (!entry) continue;

            if (GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if (utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if (len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if (utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }

                if (utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);

    if (names)
        GENERAL_NAMES_free(names);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        fprintf(stdout, "  %s: <not available>\n", label);

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("SSL Issuer (cn)", iname);

    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("SSL Subject (cn)", sname);

    if (depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("SSL Subject (san)", cert);
    }

    if (preverify == 0)
    {
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  SSL Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if (err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  SSL Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  SSL Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  SSL Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  SSL Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if (err == X509_V_OK)
            fprintf(stdout, "  SSL Error = X509_V_OK\n");
        else
            fprintf(stdout, "  SSL Error = %d\n", err);
    }

    return preverify;
    //    return 1;
}

SSLVerifyDlg::SSLVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mClearSaveURLBtn, SIGNAL(clicked()), this, SLOT(clickClearSaveURL()));
    connect( mClearURLBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mClearTrustBtn, SIGNAL(clicked()), this, SLOT(clickClearTrust()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clickClearResult()));
    connect( mCipherAddBtn, SIGNAL(clicked()), this, SLOT(clickAddCipher()));
    connect( mFixCipherNameCheck, SIGNAL(clicked()), this, SLOT(checkFixCipherName()));
    connect( mCipherClearBtn, SIGNAL(clicked()), this, SLOT(clickClearCipher()));
    connect( mHostNameCheck, SIGNAL(clicked()), this, SLOT(checkHostName()));

    connect( mURLTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));
    connect( mURLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(viewCertTableMenu()));
    connect( mURLTable, SIGNAL(clicked(QModelIndex)), this, SLOT(selectTable(QModelIndex)));
    connect( mURLTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));

    connect( mTrustCACertFindBtn, SIGNAL(clicked()), this, SLOT(findTrustCACert()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

SSLVerifyDlg::~SSLVerifyDlg()
{

}

void SSLVerifyDlg::log( const QString strLog, QColor cr )
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

void SSLVerifyDlg::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

void SSLVerifyDlg::initialize()
{
    QStringList sURLLabels = { tr( "URL" ), tr( "Port" ), tr( "DN" ), tr( "To" ), tr( "Left") };

    mURLTable->clear();
    mURLTable->horizontalHeader()->setStretchLastSection(true);
    mURLTable->setColumnCount( sURLLabels.size() );
    mURLTable->setHorizontalHeaderLabels( sURLLabels );
    mURLTable->verticalHeader()->setVisible(false);
    mURLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mURLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mURLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mURLTable->setColumnWidth( 0, 200 );
    mURLTable->setColumnWidth( 1, 60 );
    mURLTable->setColumnWidth( 2, 140 );
    mURLTable->setColumnWidth( 3, 80 );

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mURLTree->clear();
    mURLTree->header()->setVisible(false);
    mURLTree->setColumnCount(1);

    SSL_CTX *pCTX = NULL;
    JS_SSL_initClient( &pCTX );
    JStrList *pCipherList = NULL;
    JS_SSL_getCiphersList(  pCTX, &pCipherList );
    JStrList *pCurList = pCipherList;

    while( pCurList )
    {
        mCipherListCombo->addItem( pCurList->pStr );
        pCurList = pCurList->pNext;
    }

    if( pCTX ) JS_SSL_finish( &pCTX );

    if( pCipherList ) JS_UTIL_resetStrList( &pCipherList );
    checkFixCipherName();

    mHostNameCheck->click();
    tabWidget->setCurrentIndex(0);
}

QStringList SSLVerifyDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTLSUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void SSLVerifyDlg::setUsedURL( const QString strURL )
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

int SSLVerifyDlg::verifyURL( const QString strHost, int nPort )
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
    long uFlags = getFlags();

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_SSL_initClient( &pCTX );
    JS_SSL_setVerifyCallback( pCTX, SSL_VERIFY_NONE, verify_callback );

    if( mFixCipherNameCheck->isChecked() )
    {
        QString strCipher = mCipherListText->text();

        JS_SSL_setCiphersList( pCTX, strCipher.toStdString().c_str() );
    }

//    uFlags |= X509_V_FLAG_PARTIAL_CHAIN ;
    JS_SSL_setFlags( pCTX, uFlags );

    QString strTrustFolder = berApplet->settingsMgr()->trustedCAPath();
    QString strTrustCACert = mTrustCACertText->text();

    berApplet->log( QString( "TrustedPath : %1").arg( strTrustFolder ) );
    berApplet->log( QString( "TrustCACert : %1").arg( strTrustCACert ));

    if( strTrustFolder.length() >= 1 || strTrustCACert.length() >= 1 )
    {
        ret = JS_SSL_setVerifyLoaction( pCTX,
                                       strTrustCACert.length() > 0 ? strTrustCACert.toLocal8Bit().toStdString().c_str() : NULL,
                                       strTrustFolder.length() > 0 ? strTrustFolder.toLocal8Bit().toStdString().c_str() : NULL );

        if( ret == 0 )
        {
            berApplet->log( "Trust list loaded successfully" );
        }
        else
        {
            berApplet->elog( QString("fail to load trust list:%1").arg( ret ) );
        }
    }

    log( QString( "SSL Host:Port       : %1:%2" ).arg( strHost ).arg( nPort ));

    int nSockFd = JS_NET_connect( strHost.toStdString().c_str(), nPort );
    if( nSockFd < 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    ret = JS_SSL_initSSL( pCTX, nSockFd, &pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString("fail to init SSL(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    if( mHostNameCheck->isChecked() )
    {
        QString strHostName = mHostNameText->text();
        if( strHostName.length() > 0 ) JS_SSL_setHostName( pSSL, strHostName.toStdString().c_str() );
    }

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
        strLeft = QString( "%1" ).arg( left_t / 86400 );
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
    mURLTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pSubjectName ));
//    mURLTable->setItem( row, 3, new QTableWidgetItem( sNotBefore ));
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

void SSLVerifyDlg::createTree( const BINList *pCertList )
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

long SSLVerifyDlg::getFlags()
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

void SSLVerifyDlg::clickConnect()
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
    mHostNameText->setText( strHost );

    verifyURL( strHost, nPort );
    setUsedURL( strURL );
}

void SSLVerifyDlg::clickRefresh()
{
    int nCount = mURLTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mURLTable->item(0, 0);
        QTableWidgetItem *item1 = mURLTable->item(0, 1);

        QString strHost = item0->text();
        int nPort = item1->text().toInt();

        verifyURL( strHost, nPort );

        mURLTable->removeRow(0);
    }
}

void SSLVerifyDlg::clickClearURL()
{
    int nCount = mURLTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        mURLTable->removeRow(0);
    }
}

void SSLVerifyDlg::clickClearSaveURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTLSUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void SSLVerifyDlg::clickClearResult()
{
    mURLTree->clear();
    mLogText->clear();
}

void SSLVerifyDlg::findTrustCACert()
{
    QString strPath = mTrustCACertText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mTrustCACertText->setText( fileName );
}

void SSLVerifyDlg::clickClearTrust()
{
    mTrustCACertText->clear();
}

void SSLVerifyDlg::checkFixCipherName()
{
    bool bVal = mFixCipherNameCheck->isChecked();

    mCipherListCombo->setEnabled( bVal );
    mCipherAddBtn->setEnabled( bVal );
    mCipherListText->setEnabled( bVal );
    mCipherClearBtn->setEnabled( bVal );
}

void SSLVerifyDlg::checkHostName()
{
    bool bVal = mHostNameCheck->isChecked();
    mHostNameText->setEnabled( bVal );
}

void SSLVerifyDlg::clickClearCipher()
{
    mCipherListText->clear();
}

void SSLVerifyDlg::clickAddCipher()
{
    QString strCipher = mCipherListCombo->currentText();
    QString strCipherList = mCipherListText->text();

    QStringList strList = strCipherList.split( ":" );

    if( strCipherList.length() < 1 )
    {
        strCipherList = strCipher;
    }
    else
    {
        for( int i = 0; i < strList.size(); i++ )
        {
            if( strCipher == strList.at(i) ) return;
        }

        strCipherList += ":";
        strCipherList += strCipher;
    }

    mCipherListText->setText( strCipherList );
}


void SSLVerifyDlg::selectTable(QModelIndex index)
{

}

void SSLVerifyDlg::slotTableMenuRequested( QPoint pos )
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

void SSLVerifyDlg::deleteTableMenu()
{
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);
    mURLTable->removeRow(idx.row());
}

void SSLVerifyDlg::viewCertTableMenu()
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

void SSLVerifyDlg::decodeCertTableMenu()
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

void SSLVerifyDlg::slotTreeMenuRequested( QPoint pos )
{
    QTreeWidgetItem* item = mURLTree->currentItem();

    QMenu *menu = new QMenu(this);
    QAction *viewAct = new QAction( tr("View Cert"), this );
    QAction *decodeAct = new QAction( tr( "Decode Cert"), this);
    QAction *saveTrustedCAAct = new QAction( tr( "Save to trustedCA" ), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCertTreeMenu()));
    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeCertTreeMenu()));
    connect( saveTrustedCAAct, SIGNAL(triggered()), this, SLOT(saveTrustedCA()));

    menu->addAction( viewAct );
    menu->addAction( decodeAct );

    if( item->parent() == NULL )
    {
        menu->addAction( saveTrustedCAAct );
    }

    menu->popup( mURLTree->viewport()->mapToGlobal(pos));
}

void SSLVerifyDlg::viewCertTreeMenu()
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

void SSLVerifyDlg::saveTrustedCA()
{
    int ret = 0;

    BIN binDigest = {0,0};
    QString strTrustedCAPath = berApplet->settingsMgr()->trustedCAPath();

    QTreeWidgetItem *item = mURLTree->currentItem();
    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();

    BIN binCert = {0,0};
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    if( QDir( strTrustedCAPath ).exists() == false )
        QDir().mkdir( strTrustedCAPath );

    JS_PKI_genHash( "SHA1", &binCert, &binDigest );
    QString strFileName = QString( "%1/%2.pem" ).arg( strTrustedCAPath ).arg( getHexString( &binDigest ));

    if( QFileInfo::exists( strFileName ) == true )
    {
        berApplet->warningBox( tr( "The file(%1) is already existed").arg( strFileName ), this );
        goto end;
    }

    ret = JS_BIN_writePEM( &binCert, JS_PEM_TYPE_CERTIFICATE, strFileName.toLocal8Bit().toStdString().c_str() );
    if( ret > 0 )
        berApplet->messageBox( tr( "The Certificate saved to trustedCA folder"), this );
    else
        berApplet->warningBox( tr( "The Certificate fail to save to trustedCA folder:%1" ).arg(ret), this );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binDigest );
}

void SSLVerifyDlg::decodeCertTreeMenu()
{
    QTreeWidgetItem *item = mURLTree->currentItem();

    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();
    BIN binCert = {0,0};

    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    berApplet->decodeData( &binCert, "" );
    JS_BIN_reset( &binCert );
}
