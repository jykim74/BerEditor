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
#include "trust_list_dlg.h"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include "js_pki.h"

const QString kTLSUsedURL = "TLSUsedURL";
const QStringList kModeLists = { "SSL_VERIFY_NONE", "SSL_VERIFY_PEER" };

void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    char *utf8 = NULL;

    do
    {
        if (!name) break; /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (!(idx > -1))  break; /* failed */

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if (!entry) break; /* failed */

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (!data) break; /* failed */

        int length = ASN1_STRING_to_UTF8((unsigned char **)&utf8, data);
        if (!utf8 || !(length > 0))  break; /* failed */

        berApplet->log( QString( "  %1: %2").arg( label ).arg( utf8 ));
        success = 1;

    } while (0);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        berApplet->log( QString("  %1: <not available>" ).arg(label));
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    char* utf8 = NULL;

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

                len1 = ASN1_STRING_to_UTF8((unsigned char **)&utf8, entry->d.dNSName);
                if (utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if (len1 != len2) {
                    berApplet->log( QString( "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d" ).arg( len2 ).arg( len1) );
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if (utf8 && len1 && len2 && (len1 == len2)) {
                    berApplet->log( QString("  %1: %2").arg( label ).arg( utf8) );
                    success = 1;
                }

                if (utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                berApplet->elog( QString("  Unknown GENERAL_NAME type: %1").arg( entry->type) );
            }
        }

    } while (0);

    if (names)
        GENERAL_NAMES_free(names);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        berApplet->elog( QString("  %1: <not available>" ).arg(label) );

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */
    berApplet->log( "VerifyCallback" );

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
            berApplet->elog( QString("  SSL Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY") );
        else if (err == X509_V_ERR_CERT_UNTRUSTED)
            berApplet->elog( QString("  SSL Error = X509_V_ERR_CERT_UNTRUSTED"));
        else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            berApplet->elog( QString("  SSL Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"));
        else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
            berApplet->elog( QString("  SSL Error = X509_V_ERR_CERT_NOT_YET_VALID"));
        else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            berApplet->elog( QString( "  SSL Error = X509_V_ERR_CERT_HAS_EXPIRED"));
        else if (err == X509_V_OK)
            berApplet->elog( QString( "  SSL Error = X509_V_OK"));
        else
            berApplet->elog( QString("  SSL Error = %1" ).arg( err ));
    }

    return preverify;
}

SSLVerifyDlg::SSLVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    url_tree_root_ = NULL;

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mClearSaveURLBtn, SIGNAL(clicked()), this, SLOT(clickClearSaveURL()));
    connect( mClearURLBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clickClearResult()));
    connect( mCipherAddBtn, SIGNAL(clicked()), this, SLOT(clickAddCipher()));
    connect( mFixCipherNameCheck, SIGNAL(clicked()), this, SLOT(checkFixCipherName()));
    connect( mCipherClearBtn, SIGNAL(clicked()), this, SLOT(clickClearCipher()));
    connect( mViewTrustListBtn, SIGNAL(clicked()), this, SLOT(clickViewTrustList()));

    connect( mURLTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));
    connect( mURLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(viewCertTableMenu()));
    connect( mURLTable, SIGNAL(clicked(QModelIndex)), this, SLOT(selectTable(QModelIndex)));
    connect( mURLTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));


    connect( mUseMutualCheck, SIGNAL(clicked()), this, SLOT(checkUseMutual()));

    connect( mFindTrustCABtn, SIGNAL(clicked()), this, SLOT(findTrustCACert()));
    connect( mTrustCAViewBtn, SIGNAL(clicked()), this, SLOT(clickTrustCAView()));
    connect( mTrustCADecodeBtn, SIGNAL(clicked()), this, SLOT(clickTrustCADecode()));
    connect( mTrustCATypeBtn, SIGNAL(clicked()), this, SLOT(clickTrustCAType()));

    connect( mFindClientCABtn, SIGNAL(clicked()), this, SLOT(findClientCA()));
    connect( mClientCAViewBtn, SIGNAL(clicked()), this, SLOT(clickClientCAView()));
    connect( mClientCADecodeBtn, SIGNAL(clicked()), this, SLOT(clickClientCADecode()));
    connect( mClientCATypeBtn, SIGNAL(clicked()), this, SLOT(clickClientCAType()));

    connect( mFindClientCertBtn, SIGNAL(clicked()), this, SLOT(findClientCert()));
    connect( mClientCertViewBtn, SIGNAL(clicked()), this, SLOT(clickClientCertView()));
    connect( mClientCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickClientCertDecode()));
    connect( mClientCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickClientCertType()));

    connect( mFindClientPriKeyBtn, SIGNAL(clicked()), this, SLOT(findClientPriKey()));
    connect( mClientPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickClientPriKeyDecode()));
    connect( mClientPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickClientPriKeyType()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mTrustCAViewBtn->setFixedWidth(34);
    mTrustCADecodeBtn->setFixedWidth(34);
    mTrustCATypeBtn->setFixedWidth(34);

    mClientCAViewBtn->setFixedWidth(34);
    mClientCADecodeBtn->setFixedWidth(34);
    mClientCATypeBtn->setFixedWidth(34);

    mClientCertViewBtn->setFixedWidth(34);
    mClientCertDecodeBtn->setFixedWidth(34);
    mClientCertTypeBtn->setFixedWidth(34);

    mClientPriKeyDecodeBtn->setFixedWidth(34);
    mClientPriKeyTypeBtn->setFixedWidth(34);
#endif
}

SSLVerifyDlg::~SSLVerifyDlg()
{
    if( url_tree_root_ ) delete url_tree_root_;
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
    mModeCombo->addItems( kModeLists );
    mVerifyDepthText->setText( QString("%1").arg( 4 ));
    mTrustListPathText->setText( berApplet->settingsMgr()->getTrustedCAPath() );

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
    checkUseMutual();
    mAuthTab->setCurrentIndex(0);
    mURLTab->setCurrentIndex(0);

    url_tree_root_ = new QTreeWidgetItem;
    url_tree_root_->setText( 0, "Certificate Authority" );
    url_tree_root_->setIcon( 0, QIcon(":/images/ca.png"));

    mURLTree->insertTopLevelItem( 0, url_tree_root_ );
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
    int nVerifyDepth = mVerifyDepthText->text().toInt();

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( mModeCombo->currentIndex() == 0 )
    {
        JS_SSL_initClient( &pCTX );
    }
    else
    {
        JS_SSL_initClient2( &pCTX, SSL_VERIFY_PEER,verify_callback );
    }

    QString strTrustList = mTrustListPathText->text();
    QString strTrustCACert = mTrustCAPathText->text();


    if( strTrustList.length() >= 1 || strTrustCACert.length() >= 1 )
    {

        ret = JS_SSL_setVerifyLoaction( pCTX,
                                       strTrustCACert.length() > 0 ? strTrustCACert.toLocal8Bit().toStdString().c_str() : NULL,
                                       strTrustList.length() > 0 ? strTrustList.toLocal8Bit().toStdString().c_str() : NULL );

        if( ret == 0 )
        {
            berApplet->log( "Trust list loaded successfully" );
        }
        else
        {
            berApplet->elog( QString("fail to load trust list:%1").arg( ret ) );
        }
    }

    if( mFixCipherNameCheck->isChecked() )
    {
        QString strCipher = mCipherListText->text();

        JS_SSL_setCiphersList( pCTX, strCipher.toStdString().c_str() );
    }

    JS_SSL_setFlags( pCTX, uFlags );

    if( mUseMutualCheck->isChecked() )
    {
        BIN binCA = {0,0};
        BIN binCert = {0,0};
        BIN binPriKey = {0,0};

        QString strClientCAPath = mClientCAPathText->text();
        if( strClientCAPath.length() > 0 )
        {
            JS_BIN_fileReadBER( strClientCAPath.toLocal8Bit().toStdString().c_str(), &binCA );
            JS_SSL_setClientCACert( pCTX, &binCA );
            log( "Client CA is set" );
            JS_BIN_reset( &binCA );
        }

        QString strClientCertPath = mClientCAPathText->text();
        JS_BIN_fileReadBER( strClientCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
        ret = readPrivateKey( &binPriKey );

        if( binCert.nLen > 0 && binPriKey.nLen > 0 )
        {
            JS_SSL_setCertAndPriKey( pCTX, &binPriKey, &binCert );
            log( "Client certificate and private key is set" );
        }

        JS_BIN_reset( &binCert );
        JS_BIN_reset( &binPriKey );
    }

    log( "========================================================================");
    log( QString( "SSL Host:Port       : %1:%2" ).arg( strHost ).arg( nPort ));
    log( "========================================================================");

    int nSockFd = JS_NET_connect( strHost.toStdString().c_str(), nPort );
    if( nSockFd < 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    log( "Server connected successfully" );

    ret = JS_SSL_initSSL( pCTX, nSockFd, &pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString("fail to init SSL(%1:%2)").arg( strHost ).arg( nPort ));
        goto end;
    }

    if( nVerifyDepth > 0 )
    {
        SSL_set_verify_depth( pSSL, nVerifyDepth );
        log( QString( "Verify Depth: %1" ).arg( nVerifyDepth ));
    }

    if( mHostNameCheck->isChecked() )
    {
        JS_SSL_setHostName( pSSL, strHost.toStdString().c_str() );
        log( QString( "TLS SetHostName: %1").arg( strHost ));
    }

    ret = JS_SSL_connect( pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to connect SSL:%1").arg( ret ));
        goto end;
    }

    log( QString( "SSL connected successfully" ) );
    log( QString( "Current TLS Version : %1").arg( JS_SSL_getCurrentVersionName( pSSL )));
    log( QString( "Current Cipher Name : %1").arg( JS_SSL_getCurrentCipherName( pSSL ) ));


    ret = JS_SSL_getChains( pSSL, &pCertList );
    count = JS_BIN_countList( pCertList );
    berApplet->log( QString( "Chain Count: %1").arg( count ) );

    ret = JS_SSL_verifyCert( pSSL );
    log( QString( "Verify Certificate  : %1(%2)").arg( X509_verify_cert_error_string(ret)).arg( ret ));

    pAtList = JS_BIN_getListAt( 0, pCertList );
    ret = JS_PKI_getCertInfo( &pAtList->Bin, &sCertInfo, NULL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "Invalid certificate data: %1").arg( ret ));
        goto end;
    }

    log( QString( "The Subject is %1" ).arg( sCertInfo.pSubjectName ));

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

    if( isExistURL( strHost, nPort ) == false )
    {
        mURLTable->insertRow( row );
        mURLTable->setRowHeight( row, 10 );
        mURLTable->setItem( row, 0, item );
        mURLTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nPort )));
        mURLTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pSubjectName ));
//      mURLTable->setItem( row, 3, new QTableWidgetItem( sNotBefore ));
        mURLTable->setItem( row, 3, new QTableWidgetItem( sNotAfter ));
        mURLTable->setItem( row, 4, new QTableWidgetItem( strLeft ));

        createTree( pCertList );
    }
    else
    {
        log( "This URL is already exist in URL List" );
    }

    log( "========================================================================");

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

    BIN binCert = {0,0};

    if( pCertList == NULL ) return;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    nCount = JS_BIN_countList( pCertList );

    if( nCount < 1 ) return;
    pAtList = JS_BIN_getListAt( 0, pCertList );
    JS_BIN_copy( &binCert, &pAtList->Bin );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    QTreeWidgetItem *item = new QTreeWidgetItem;
    item->setText( 0, sCertInfo.pSubjectName );
    item->setData( 0, Qt::UserRole, getHexString( &binCert ));
    item->setIcon( 0, QIcon(":/images/cert.png"));

    JS_PKI_resetCertInfo( &sCertInfo );

    last = item;

    if( nCount > 1 )
    {
        for( int i = 1; i < nCount; i++ )
        {
            for( int k = 1; k < nCount; k++ )
            {
                pAtList = JS_BIN_getListAt( k, pCertList );
                if( JS_PKI_isIssuerDNCert( &pAtList->Bin, &binCert ) == 1 )
                {
                    int bSelfSign = 0;

                    ret = JS_PKI_getCertInfo2( &pAtList->Bin, &sCertInfo, NULL, &bSelfSign );

                    item = new QTreeWidgetItem;
                    item->setText( 0, sCertInfo.pSubjectName );
                    item->setData( 0, Qt::UserRole, getHexString( &pAtList->Bin ));

                    if( bSelfSign == 1 )
                        item->setIcon( 0, QIcon(":/images/root_cert.png"));
                    else
                        item->setIcon( 0, QIcon(":/images/cert.png"));

                    item->addChild( last );
                    JS_PKI_resetCertInfo( &sCertInfo );
                    JS_BIN_reset( &binCert );
                    JS_BIN_copy( &binCert, &pAtList->Bin );
                    last = item;

                    break;
                }
            }
        }
    }

//    mURLTree->insertTopLevelItem( 0, item );
    url_tree_root_->insertChild( 0, item );
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
    QStringList list = strURL.split( "://" );

    if( list.size() < 2 )
    {
        QString strScheme = "HTTPS://";
        strURL = QString( "%1%2").arg( strScheme ).arg( strURL );
    }

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
    if( strURL.length() > 1 ) setUsedURL( strURL );
}

void SSLVerifyDlg::clickRefresh()
{
    clickClearResult();

    int nCount = mURLTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mURLTable->item(0, 0);
        QTableWidgetItem *item1 = mURLTable->item(0, 1);

        QString strHost = item0->text();
        int nPort = item1->text().toInt();

        mURLTable->removeRow(0);

        verifyURL( strHost, nPort );
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
    mLogText->clear();

    int count = url_tree_root_->childCount();
    for( int i=0; i < count; i++ )
    {
        QTreeWidgetItem* child = url_tree_root_->child(0);
        url_tree_root_->removeChild(child);
    }
}

void SSLVerifyDlg::findTrustCACert()
{
    QString strPath = mTrustCAPathText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mTrustCAPathText->setText( fileName );
}

void SSLVerifyDlg::checkFixCipherName()
{
    bool bVal = mFixCipherNameCheck->isChecked();

    mCipherListCombo->setEnabled( bVal );
    mCipherAddBtn->setEnabled( bVal );
    mCipherListText->setEnabled( bVal );
    mCipherClearBtn->setEnabled( bVal );
}


void SSLVerifyDlg::clickClearCipher()
{
    mCipherListText->clear();
}

void SSLVerifyDlg::clickViewTrustList()
{
    TrustListDlg trustList;
    trustList.exec();
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

    if( item->parent() == url_tree_root_ )
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
    long uHash = 0;

    QString strTrustedCAPath = berApplet->settingsMgr()->trustedCAPath();

    QTreeWidgetItem *item = mURLTree->currentItem();
    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();

    BIN binCert = {0,0};
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    if( JS_PKI_isSelfSignedCert( &binCert ) != 1 )
    {
        JS_BIN_reset( &binCert );
        berApplet->warningBox( tr( "This certificate is not self-signed" ), this );
        return;
    }

    if( QDir( strTrustedCAPath ).exists() == false )
        QDir().mkdir( strTrustedCAPath );

    JS_PKI_getSubjectNameHash( &binCert, &uHash );
    berApplet->log( QString( "Subject Hash: %1").arg( uHash, 8, 16, QLatin1Char( '0') ));
    QString strFileName = QString( "%1/%2.0" ).arg( strTrustedCAPath ).arg( uHash, 8, 16, QLatin1Char('0'));

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
}

void SSLVerifyDlg::checkUseMutual()
{
    bool bVal = mUseMutualCheck->isChecked();

    mAuthTab->setTabEnabled( 1, bVal );
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

int SSLVerifyDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mClientPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select private key"), this );
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to read private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswordText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "You have to insert password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt private key:%1").arg( ret ), this );
            mPasswordText->setFocus();
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

void SSLVerifyDlg::clickTrustCAView()
{
    QString strPath = mTrustCAPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLVerifyDlg::clickTrustCADecode()
{
    BIN binData = {0,0};
    QString strPath = mTrustCAPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLVerifyDlg::clickTrustCAType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mTrustCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find sign certificate"), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Sign Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLVerifyDlg::findClientCA()
{
    QString strPath = mClientCAPathText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mClientCAPathText->setText( fileName );
}

void SSLVerifyDlg::clickClientCAView()
{
    QString strPath = mClientCAPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLVerifyDlg::clickClientCADecode()
{
    BIN binData = {0,0};
    QString strPath = mClientCAPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLVerifyDlg::clickClientCAType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mClientCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find sign certificate"), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Sign Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLVerifyDlg::findClientCert()
{
    QString strPath = mClientCertPathText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mClientCertPathText->setText( fileName );
}

void SSLVerifyDlg::clickClientCertView()
{
    QString strPath = mClientCertPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLVerifyDlg::clickClientCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mClientCertPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLVerifyDlg::clickClientCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mClientCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find sign certificate"), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Sign Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLVerifyDlg::findClientPriKey()
{
    QString strPath = mClientPriKeyPathText->text();
    if( strPath.length() < 1 )
        strPath = berApplet->curFolder();

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() > 1 ) mClientPriKeyPathText->setText( fileName );
}

void SSLVerifyDlg::clickClientPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mClientPriKeyPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLVerifyDlg::clickClientPriKeyType()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) return;
    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "KM Private Key Type is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

bool SSLVerifyDlg::isExistURL( const QString strHost, int nPort )
{
    int count = mURLTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        QTableWidgetItem* item0 = mURLTable->item( i, 0 );
        QTableWidgetItem* item1 = mURLTable->item(i, 1);

        if( item0->text().toLower() == strHost.toLower() && item1->text().toInt() == nPort )
            return true;
    }

    return false;
}
