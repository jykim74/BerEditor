/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QUrl>
#include <QDateTime>
#include <QSettings>
#include <QMenu>
#include <QDir>
#include <QFile>

#include "common.h"
#include "ssl_check_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_util.h"
#include "js_error.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"

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

SSLCheckDlg::SSLCheckDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    url_tree_root_ = NULL;

    connect( mCheckBtn, SIGNAL(clicked()), this, SLOT(clickCheck()));
    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(clickRefresh()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearLogBtn, SIGNAL(clicked()), this, SLOT(clickClearLog()));

    connect( mClearSaveURLBtn, SIGNAL(clicked()), this, SLOT(clickClearSaveURL()));
    connect( mClearURLBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clickClearResult()));
    connect( mCipherAddBtn, SIGNAL(clicked()), this, SLOT(clickAddCipher()));
    connect( mFixCipherNameCheck, SIGNAL(clicked()), this, SLOT(checkFixCipherName()));
    connect( mCipherClearBtn, SIGNAL(clicked()), this, SLOT(clickClearCipher()));
    connect( mViewTrustListBtn, SIGNAL(clicked()), this, SLOT(clickViewTrustList()));
    connect( mShowInfoBtn, SIGNAL(clicked()), this, SLOT(clickShowInfo()));

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
    connect( mClientPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickClientPriKeyView()));
    connect( mClientPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickClientPriKeyDecode()));
    connect( mClientPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickClientPriKeyType()));

    initialize();
    mCheckBtn->setDefault(true);

    mTreeTab->layout()->setSpacing(0);
    mTreeTab->layout()->setMargin(0);
    mLogTab->layout()->setSpacing(0);
    mLogTab->layout()->setMargin(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mServerTab->layout()->setSpacing(5);
    mServerTab->layout()->setMargin(5);
    mMutualTab->layout()->setSpacing(5);
    mMutualTab->layout()->setMargin(5);

    mTrustCAViewBtn->setFixedWidth(34);
    mTrustCADecodeBtn->setFixedWidth(34);
    mTrustCATypeBtn->setFixedWidth(34);

    mClientCAViewBtn->setFixedWidth(34);
    mClientCADecodeBtn->setFixedWidth(34);
    mClientCATypeBtn->setFixedWidth(34);

    mClientCertViewBtn->setFixedWidth(34);
    mClientCertDecodeBtn->setFixedWidth(34);
    mClientCertTypeBtn->setFixedWidth(34);

    mClientPriKeyViewBtn->setFixedWidth(34);
    mClientPriKeyDecodeBtn->setFixedWidth(34);
    mClientPriKeyTypeBtn->setFixedWidth(34);

    mClearSaveURLBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SSLCheckDlg::~SSLCheckDlg()
{
    if( url_tree_root_ ) delete url_tree_root_;
}

void SSLCheckDlg::log( const QString strLog, QColor cr )
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

void SSLCheckDlg::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

void SSLCheckDlg::initialize()
{
    mModeCombo->addItems( kModeLists );
    mVerifyDepthText->setText( QString("%1").arg( 4 ));

    QStringList sURLLabels = { tr( "URL" ), tr( "Port" ), tr( "DN" ), tr( "To" ) };

    mURLTable->clear();
    mURLTable->horizontalHeader()->setStretchLastSection(true);
    mURLTable->setColumnCount( sURLLabels.size() );
    mURLTable->setHorizontalHeaderLabels( sURLLabels );
    mURLTable->verticalHeader()->setVisible(false);
    mURLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mURLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mURLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mURLTable->setColumnWidth( 0, 240 );
    mURLTable->setColumnWidth( 1, 40 );
    mURLTable->setColumnWidth( 2, 200 );

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mURLCombo->setCurrentText("");

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

    mClientCAPathText->setPlaceholderText( tr("Select CertMan CA certificate") );
    mClientCertPathText->setPlaceholderText( tr("Select CertMan certificate") );
    mClientPriKeyPathText->setPlaceholderText( tr("Select CertMan private key") );

    mTrustCAPathText->setPlaceholderText( tr("Find a trusted CA certificate") );
    mURLLabel->setText( tr( "Enter a URL (ex https://www.google.com, www.naver.com)") );
}

QStringList SSLCheckDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTLSUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void SSLCheckDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTLSUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTLSUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

int SSLCheckDlg::verifyURL( const QString strHost, int nPort, BIN *pCA )
{
    int ret = 0;
    int count = 0;
    bool bGood = true;

    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;
    BINList *pCertList = NULL;
    const BINList *pAtList = NULL;
    JCertInfo sCertInfo;
    char    sNotBefore[64];
    char    sNotAfter[64];

    BIN binClientCA = {0,0};
    BIN binClientCert = {0,0};
    BIN binClientPriKey = {0,0};

    int row = mURLTable->rowCount();
    time_t now_t = time( NULL );
    time_t left_t = 0;
    QString strLeft;
    QTableWidgetItem *item = new QTableWidgetItem( strHost );
    long uFlags = getFlags();
    int nVerifyDepth = mVerifyDepthText->text().toInt();

    QDateTime dateTime;
    dateTime.setSecsSinceEpoch(time(NULL));

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( mModeCombo->currentIndex() == 0 )
    {
        JS_SSL_initClient( &pCTX );
    }
    else
    {
        JS_SSL_initClient2( &pCTX, SSL_VERIFY_PEER,verify_callback );
    }

    QString strTrustList = berApplet->settingsMgr()->trustCertPath();
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
            berApplet->elog( QString("failed to load trust list:%1").arg( ret ) );
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

        QString strClientCAPath = mClientCAPathText->text();

        if( strClientCAPath.length() < 1 )
        {
            CertManDlg certMan;
            certMan.setMode(ManModeSelCA);
            certMan.setTitle( tr( "Select client CA certificate" ));
            if( certMan.exec() == QDialog::Accepted )
            {
                strClientCAPath = certMan.getSeletedCAPath();
                mClientCAPathText->setText( strClientCAPath );
            }
        }

        if( strClientCAPath.length() > 0 )
        {
            JS_BIN_fileReadBER( strClientCAPath.toLocal8Bit().toStdString().c_str(), &binClientCA );
        }

        if( mCertGroup->isChecked() )
        {
            QString strClientCertPath = mClientCAPathText->text();

            if( strClientCertPath.length() > 0 )
                JS_BIN_fileReadBER( strClientCertPath.toLocal8Bit().toStdString().c_str(), &binClientCert );

            ret = readPrivateKey( &binClientPriKey );
        }
        else
        {
            CertManDlg certMan;
            QString strPriHex;
            QString strCertHex;

            certMan.setMode( ManModeSelBoth );
            certMan.setTitle( tr( "Select a client certificate") );

            if( certMan.exec() == QDialog::Accepted )
            {
                strPriHex = certMan.getPriKeyHex();
                strCertHex = certMan.getCertHex();

                JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binClientPriKey );
                JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binClientCert );
            }
        }
    }

    log( "===================================================================");
    log( QString( "SSL Host:Port       : %1:%2" ).arg( strHost ).arg( nPort ));
    log( "-------------------------------------------------------------------");

    int nSockFd = JS_NET_connect( strHost.toStdString().c_str(), nPort );
    if( nSockFd < 0 )
    {
        berApplet->elog( QString("fail to connect Server(%1:%2)").arg( strHost ).arg( nPort ));
        ret = ret = JSR_SERVER_CONNECT_FAIL;
        goto end;
    }

    log( QString( "Check time          : %1").arg( dateTime.toString("yyyy-MM-dd HH:mm:ss") ) );
    log( "Server connection   : OK" );

    ret = JS_SSL_initSSL( pCTX, nSockFd, &pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString("failed to initialize SSL(%1:%2)").arg( strHost ).arg( nPort ));
        ret = JSR_SSL_INIT_FAIL;
        goto end;
    }

    if( binClientCA.nLen > 0 )
        JS_SSL_setClientCACert( pCTX, &binClientCA );

    if( binClientPriKey.nLen > 0 && binClientCert.nLen > 0 )
    {
        JS_SSL_setCertAndPriKey( pCTX, &binClientPriKey, &binClientCert );
        log( "Mutual Auth         : OK" );
    }

    if( nVerifyDepth > 0 )
    {
        SSL_set_verify_depth( pSSL, nVerifyDepth );
        log( QString( "Verify depth        : %1" ).arg( nVerifyDepth ));
    }

    JS_SSL_setTLSExtHostName( pSSL, strHost.toStdString().c_str() );

    ret = JS_SSL_connect( pSSL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "failed to handshake SSL [%1]").arg( ret ));
        elog( QString( "Handshake           : Fail [ %1 ]" ).arg( ret ) );
        ret = JSR_SSL_CONNECT_FAIL;
    }
    else
    {
        log( QString( "Handshake           : OK" ) );
        log( QString( "TLS Version         : %1").arg( JS_SSL_getCurrentVersionName( pSSL )));
        log( QString( "CipherSuiteName     : %1").arg( JS_SSL_getCurrentCipherName( pSSL ) ));
    }

    JS_SSL_getChains( pSSL, &pCertList );
    count = JS_BIN_countList( pCertList );
    log( QString( "Server certificates : %1 counts").arg( count ) );

    if( ret == 0 )
    {
        ret = JS_SSL_verifyCert( pSSL );
        if( ret != 0)
        {
            bGood = false;
            elog( QString( "Verification        : Fail [ %1(%2) ]").arg( X509_verify_cert_error_string(ret)).arg( ret ));

            // ret == 20 (unable to get local issuer certificate)

            if( ret == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY || ret == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN )
                ret = JSR_SSL_LOCAL_ISSUER_CERT;
            else
                ret = JSR_INVALID;
        }
        else
        {
            log( QString( "Verification        : OK" ));
            ret = JSR_VERIFY;
        }
    }

    pAtList = JS_BIN_getListAt( 0, pCertList );
    if( pAtList == NULL ) goto end;

    if( pCA != NULL && count > 1 )
    {
        JS_BIN_copy( pCA, &(JS_BIN_getListAt( count - 1, pCertList )->Bin) );
    }

    if( JS_PKI_getCertInfo( &pAtList->Bin, &sCertInfo, NULL ) != 0 )
    {
        berApplet->elog( QString( "Invalid certificate [%1]").arg( ret ));
        ret = JSR_PKI_GET_CERT_FAIL;
        goto end;
    }

    if( mHostNameCheck->isChecked() && ret == JSR_VERIFY )
    {
        QString strRes;
        ret = JS_SSL_checkHostName( &pAtList->Bin, strHost.toStdString().c_str() );

        if( ret == 1 )
        {
            strRes = "Valid";
            log( QString( "Hostname check      : %1 (%2 : %3)").arg( strHost ).arg( strRes ).arg( ret ));
            ret = JSR_VERIFY;
        }
        else if( ret == 0)
        {
            bGood = false;
            strRes = "NameMismatch";
            elog( QString( "Hostname check      : %1 (%2 : %3)").arg( strHost ).arg( strRes ).arg( ret ));
            ret = JSR_SSL_HOST_NAME_MISMATCH;
        }
        else
        {
            bGood = false;
            strRes = "Error";
            elog( QString( "Hostname check      : %1 (%2 : %3)").arg( strHost ).arg( strRes ).arg( ret ));
        }
    }

    log( QString( "Subject Name        : %1" ).arg( sCertInfo.pSubjectName ));

    JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
    JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );
    left_t = ( sCertInfo.tNotAfter - now_t );

    if( left_t > 0 )
    {
        strLeft = QString( "%1" ).arg( left_t / 86400 );
        if( bGood == true )
            item->setIcon(QIcon(":/images/valid.png"));
        else
            item->setIcon(QIcon(":/images/invalid.png"));
    }
    else
    {
        strLeft = "Expired";
        item->setIcon(QIcon(":/image/cert_revoked.png"));
    }

    item->setData( Qt::UserRole, getHexString( &pAtList->Bin ));
    removeExistURL( strHost, nPort );

    row = 0;
    mURLTable->insertRow( row );
    mURLTable->setRowHeight( row, 10 );
    mURLTable->setItem( row, 0, item );
    mURLTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nPort )));
    mURLTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pSubjectName ));
//      mURLTable->setItem( row, 3, new QTableWidgetItem( sNotBefore ));
    mURLTable->setItem( row, 3, new QTableWidgetItem( sNotAfter ));

    createTree( strHost, nPort, pCertList, bGood );

    log( "===================================================================");

end :
    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );

    if( pCertList ) JS_BIN_resetList( &pCertList );
    JS_PKI_resetCertInfo( &sCertInfo );

    JS_BIN_reset( &binClientCA );
    JS_BIN_reset( &binClientPriKey );
    JS_BIN_reset( &binClientCert );

    return ret;
}

const QTreeWidgetItem* SSLCheckDlg::createTree( const QString strHost, int nPort, const BINList *pCertList, bool bGood )
{
    int ret = 0;
    int nCount = 0;
    const BINList *pAtList = NULL;
    JCertInfo sCertInfo;
    QTreeWidgetItem *last = NULL;

    BIN binCert = {0,0};

    if( pCertList == NULL ) return NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    nCount = JS_BIN_countList( pCertList );

    if( nCount < 1 ) return NULL;
    pAtList = JS_BIN_getListAt( 0, pCertList );
    JS_BIN_copy( &binCert, &pAtList->Bin );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    QTreeWidgetItem *itemHost = new QTreeWidgetItem;
    itemHost->setText( 0, QString( "%1:%2" ).arg( strHost ).arg( nPort ));

    if( bGood == true )
        itemHost->setIcon( 0, QIcon(":/images/valid.png"));
    else
        itemHost->setIcon( 0, QIcon(":/images/invalid.png"));

    url_tree_root_->insertChild( 0, itemHost );

    QTreeWidgetItem *item = new QTreeWidgetItem;
    item->setText( 0, sCertInfo.pSubjectName );
    item->setData( 0, Qt::UserRole, getHexString( &binCert ));

    if( bGood == true )
        item->setIcon( 0, QIcon(":/images/cert.png"));
    else
        item->setIcon( 0, QIcon(":/images/cert_revoked.png"));

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
                    item->setData( 0, 99, bSelfSign );

                    if( bSelfSign == 1 )
                    {
                        item->setIcon( 0, QIcon(":/images/root_cert.png"));
                    }
                    else
                    {
                        item->setIcon( 0, QIcon(":/images/cert.png"));
                    }

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
//    url_tree_root_->insertChild( 0, item );
    itemHost->insertChild(0, item);
    mURLTree->expandAll();
    return itemHost;
}

long SSLCheckDlg::getFlags()
{
    long uFlags = 0;

    if( mNoSSL2Check->isChecked() )
        uFlags |= SSL_OP_NO_SSLv2;

    if( mNoSSL3Check->isChecked() )
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

void SSLCheckDlg::clickCheck()
{
    int ret = 0;
    QString strHost;
    int nPort = 443;
    QUrl url;

    QString strURL = mURLCombo->currentText();
    BIN binCA = {0,0};

    if( strURL.length() < 2 )
    {
        berApplet->warningBox( tr( "Insert URL" ), this );
        mURLCombo->setFocus();
        return;
    }

    QStringList list = strURL.split( "://" );


    if( list.size() < 2 )
    {
        QString strScheme = "https://";
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

    ret = verifyURL( strHost, nPort, &binCA );
    if( strHost.length() > 3 )
    {
        setUsedURL( strURL );
    }

    if( ret == JSR_VERIFY)
    {
        berApplet->messageLog( tr( "Verify successful : %1").arg( ret ), this );
    }
    else
    {
        berApplet->warnLog( tr( "Verify failed : %1").arg( ret ), this );
        if( binCA.nLen > 0 )
        {
            if( ret == JSR_SSL_LOCAL_ISSUER_CERT )
                checkRootAndTrust( &binCA, strHost, nPort );
        }
    }

    mURLCombo->setCurrentText("");
    JS_BIN_reset( &binCA );
}

void SSLCheckDlg::checkRootAndTrust( const BIN *pCA, const QString strHost, int nPort )
{
    int ret = 0;
    int bSelfSign = 0;
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtList = NULL;
    bool bAsk = false;
    QString strMsg;
    BIN binRoot = {0,0};
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();
    unsigned long uHash = 0;
    QString strFileName;
    QString strSaveName;

    QDir dir;

    if( dir.exists(strTrustPath) == false )
        dir.mkdir( strTrustPath );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo2( pCA, &sCertInfo, &pExtList, &bSelfSign );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "Invalid certificate : %1" ).arg(ret), this );
        goto end;
    }

    if( bSelfSign != 1 )
    {
        QString strExtAIA;
        strMsg = tr( "There is no root certificate in SSL. Would you like to retrieve the root certificate from certificate information?" );
        bAsk = berApplet->yesOrNoBox( strMsg, this );

        if( bAsk == false ) goto end;

        while( 1 )
        {
            strExtAIA = CertInfoDlg::getValueFromExtList( kExtNameAIA, pExtList );
            ret = CertInfoDlg::getCA( strExtAIA, &binRoot );
            if( ret != 0 )
            {
                berApplet->warnLog( tr( "fail to get RootCA : %1").arg( ret ), this );
                goto end;
            }

            JS_PKI_resetCertInfo( &sCertInfo );
            if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );

            ret = JS_PKI_getCertInfo2( &binRoot, &sCertInfo, &pExtList, &bSelfSign );
            if( ret != 0 )
            {
                berApplet->warnLog( tr( "Invalid certificate : %1" ).arg(ret), this );
                goto end;
            }

            if( bSelfSign == true )
            {
                break;
            }
            else
            {
                JS_BIN_reset( &binRoot );
                berApplet->log( tr("This ceriticate is not root( DN: %1)" ).arg( sCertInfo.pSubjectName ) );
            }
        }
    }
    else
    {
        JS_BIN_copy( &binRoot, pCA );
    }

    strMsg = tr( "Would you like to add that root certificate to the trust list and verify it again?" );
    bAsk = berApplet->yesOrNoBox( strMsg, this );

    if( bAsk == false ) goto end;

    ret = JS_PKI_getSubjectNameHash( &binRoot, &uHash );
    if( ret != 0 ) goto end;

    strFileName = QString( "%1.0" ).arg( uHash, 8, 16, QLatin1Char('0'));
    strSaveName = QString( "%1/%2" ).arg( strTrustPath ).arg( strFileName );
    if( QFileInfo::exists( strFileName ) == true )
    {
        berApplet->warningBox( tr( "The file(%1) is already existed").arg( strSaveName ), this );
        goto end;
    }

    ret = JS_BIN_writePEM( &binRoot, JS_PEM_TYPE_CERTIFICATE, strSaveName.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "The Certificate failed to save to trustedCA folder:%1" ).arg(ret), this );
        goto end;
    }

    ret = verifyURL( strHost, nPort );
    if( ret == JSR_VERIFY)
    {
        berApplet->messageLog( tr( "Verify successful : %1").arg( ret ), this );
    }
    else
    {
        berApplet->warnLog( tr( "Verify failed : %1").arg( ret ), this );
    }

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binRoot );
    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );
}

void SSLCheckDlg::clickRefresh()
{
    int ret = 0;
//    clickClearResult();

    int nCount = mURLTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mURLTable->item(0, 0);
        QTableWidgetItem *item1 = mURLTable->item(0, 1);

        QString strHost = item0->text();
        int nPort = item1->text().toInt();

//        mURLTable->removeRow(0);

        ret = verifyURL( strHost, nPort );

        if( ret == JSR_VERIFY)
            berApplet->log( tr( "Verify successful : %1").arg( ret ) );
        else
            berApplet->elog( tr( "Verify failed : %1").arg( ret ) );
    }
}

void SSLCheckDlg::clickClearURL()
{
    mURLTable->setRowCount(0);
}

void SSLCheckDlg::clickClearSaveURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTLSUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void SSLCheckDlg::clickClearResult()
{
    mLogText->clear();

    int count = url_tree_root_->childCount();
    for( int i=0; i < count; i++ )
    {
        QTreeWidgetItem* child = url_tree_root_->child(0);
        url_tree_root_->removeChild(child);
    }
}

void SSLCheckDlg::clickClearLog()
{
    mLogText->clear();
}

void SSLCheckDlg::clickShowInfo()
{
    mInfoDock->show();
}

void SSLCheckDlg::findTrustCACert()
{
    QString strPath = mTrustCAPathText->text();


    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mTrustCAPathText->setText( fileName );
}

void SSLCheckDlg::checkFixCipherName()
{
    bool bVal = mFixCipherNameCheck->isChecked();

    mCipherListCombo->setEnabled( bVal );
    mCipherAddBtn->setEnabled( bVal );
    mCipherListText->setEnabled( bVal );
    mCipherClearBtn->setEnabled( bVal );
}


void SSLCheckDlg::clickClearCipher()
{
    mCipherListText->clear();
}

void SSLCheckDlg::clickViewTrustList()
{
//    TrustListDlg trustList;
//    trustList.exec();
    CertManDlg certMan;
    certMan.setMode( ManModeTrust );
    certMan.setTitle( tr( "Trust RootCA List" ) );
    certMan.exec();
}

void SSLCheckDlg::clickAddCipher()
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


void SSLCheckDlg::selectTable(QModelIndex index)
{

}

void SSLCheckDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction *verifyAct = new QAction( tr("Verify" ), this );
    QAction *delAct = new QAction( tr( "Delete" ), this );
    QAction *viewAct = new QAction( tr("View Cert"), this );
    QAction *decodeAct = new QAction( tr( "Decode Cert"), this);

    connect( verifyAct, SIGNAL(triggered()), this, SLOT(verifyTableMenu()));
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteTableMenu()));
    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCertTableMenu()));
    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeCertTableMenu()));

    menu->addAction( verifyAct );
    menu->addAction( delAct );
    menu->addAction( viewAct );
    menu->addAction( decodeAct );

    menu->popup( mURLTable->viewport()->mapToGlobal(pos));
}

void SSLCheckDlg::verifyTableMenu()
{
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item0 = mURLTable->item(idx.row(), 0);
    QTableWidgetItem *item1 = mURLTable->item(idx.row(), 1);

    QString strHost = item0->text();
    int nPort = item1->text().toInt();

    verifyURL( strHost, nPort );
}

void SSLCheckDlg::deleteTableMenu()
{
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);
    mURLTable->removeRow(idx.row());
}

void SSLCheckDlg::viewCertTableMenu()
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

void SSLCheckDlg::decodeCertTableMenu()
{
    BIN binCert = {0,0};
    QModelIndex idx = mURLTable->currentIndex();
    QTableWidgetItem *item = mURLTable->item(idx.row(), 0);

    if( item == NULL ) return;

    QString strData = item->data(Qt::UserRole).toString();
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    berApplet->decodeData( &binCert, "SSL Certificate" );
    JS_BIN_reset( &binCert );
}

void SSLCheckDlg::slotTreeMenuRequested( QPoint pos )
{
    QTreeWidgetItem* item = mURLTree->currentItem();
    if( item == NULL || item == url_tree_root_ ) return;

    QTreeWidgetItem* parent = item->parent();
    if( parent == NULL || parent == url_tree_root_ ) return;

    QMenu *menu = new QMenu(this);
    QAction *viewAct = new QAction( tr("View Cert"), this );
    QAction *decodeAct = new QAction( tr( "Decode Cert"), this);
    QAction *saveTrustedCAAct = new QAction( tr( "Save to trustedCA" ), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCertTreeMenu()));
    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeCertTreeMenu()));
    connect( saveTrustedCAAct, SIGNAL(triggered()), this, SLOT(saveTrustedCA()));

    menu->addAction( viewAct );
    menu->addAction( decodeAct );
    int bSelfSign = item->data( 0, 99 ).toInt();

    if( bSelfSign == 1 )
    {
        menu->addAction( saveTrustedCAAct );
    }

    menu->popup( mURLTree->viewport()->mapToGlobal(pos));
}

void SSLCheckDlg::viewCertTreeMenu()
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

void SSLCheckDlg::saveTrustedCA()
{
    int ret = 0;
    unsigned long uHash = 0;
    QDir dir;

    QString strTrustedCAPath = berApplet->settingsMgr()->trustCertPath();

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

    if( dir.exists( strTrustedCAPath ) == false )
    {
        if( dir.mkdir( strTrustedCAPath ) == false )
        {
            berApplet->warningBox( tr( "fail to mkdir:%1").arg( strTrustedCAPath), this);
            return;
        }
    }

    JS_PKI_getSubjectNameHash( &binCert, &uHash );
    berApplet->log( QString( "Subject Hash: %1").arg( uHash, 8, 16, QLatin1Char( '0') ));
    QString strFileName = QString( "%1/%2.0" ).arg( strTrustedCAPath ).arg( uHash, 8, 16, QLatin1Char('0'));

    if( QFileInfo::exists( strFileName ) == true )
    {
        berApplet->warningBox( tr( "The file(%1) is already existed").arg( strFileName ), this );
        goto end;
    }

    ret = CertManDlg::writeNameHash( strTrustedCAPath, &binCert );
    if( ret > 0 )
        berApplet->messageBox( tr( "The Certificate saved to trusted CA directory"), this );
    else
        berApplet->warningBox( tr( "The Certificate failed to save to trusted CA directory [%1]" ).arg(ret), this );

end :
    JS_BIN_reset( &binCert );
}

void SSLCheckDlg::checkUseMutual()
{
    bool bVal = mUseMutualCheck->isChecked();

    mAuthTab->setTabEnabled( 1, bVal );
}

void SSLCheckDlg::decodeCertTreeMenu()
{
    QTreeWidgetItem *item = mURLTree->currentItem();

    if( item == NULL ) return;

    QString strData = item->data(0, Qt::UserRole).toString();
    BIN binCert = {0,0};

    JS_BIN_decodeHex( strData.toStdString().c_str(), &binCert );

    berApplet->decodeData( &binCert, "SSL Certificate" );
    JS_BIN_reset( &binCert );
}

int SSLCheckDlg::readPrivateKey( BIN *pPriKey )
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
        berApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        mClientPriKeyPathText->setFocus();
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswordText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            mPasswordText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "failed to decrypt private key:%1").arg( ret ), this );
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

void SSLCheckDlg::clickTrustCAView()
{
    QString strPath = mTrustCAPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mTrustCAPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLCheckDlg::clickTrustCADecode()
{
    BIN binData = {0,0};
    QString strPath = mTrustCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mTrustCAPathText->text();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLCheckDlg::clickTrustCAType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mTrustCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate"), this );
        mTrustCAPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLCheckDlg::findClientCA()
{
    QString strPath = mClientCAPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mClientCAPathText->setText( fileName );
}

void SSLCheckDlg::clickClientCAView()
{
    QString strPath = mClientCAPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mClientCAPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLCheckDlg::clickClientCADecode()
{
    BIN binData = {0,0};
    QString strPath = mClientCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mClientCAPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLCheckDlg::clickClientCAType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mClientCAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate"), this );
        mClientCAPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLCheckDlg::findClientCert()
{
    QString strPath = mClientCertPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() > 1 ) mClientCertPathText->setText( fileName );
}

void SSLCheckDlg::clickClientCertView()
{
    QString strPath = mClientCertPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mClientCertPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SSLCheckDlg::clickClientCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mClientCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mClientCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLCheckDlg::clickClientCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mClientCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate"), this );
        mClientCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate Type is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SSLCheckDlg::findClientPriKey()
{
    QString strPath = mClientPriKeyPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() > 1 ) mClientPriKeyPathText->setText( fileName );
}

void SSLCheckDlg::clickClientPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mClientPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a private key", this );
        mClientPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SSLCheckDlg::clickClientPriKeyView()
{
    int ret = 0;
    BIN binPri = {0,0};
    PriKeyInfoDlg priKeyInfo;

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) return;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void SSLCheckDlg::clickClientPriKeyType()
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

int SSLCheckDlg::removeExistURL( const QString strHost, int nPort )
{
    int count = mURLTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        QTableWidgetItem* item0 = mURLTable->item( i, 0 );
        QTableWidgetItem* item1 = mURLTable->item(i, 1);

        if( item0->text().toLower() == strHost.toLower() && item1->text().toInt() == nPort )
        {
            mURLTable->removeRow(i);
            break;
        }
    }

    count = url_tree_root_->childCount();
    for( int i = 0; i < count; i++ )
    {
        QTreeWidgetItem *item = url_tree_root_->child(i);
        QString strName = QString( "%1:%2" ).arg( strHost ).arg( nPort );

        if( item->text(0).toLower() == strName.toLower() )
        {
            url_tree_root_->removeChild( item );
            break;
        }
    }

    return 0;
}
