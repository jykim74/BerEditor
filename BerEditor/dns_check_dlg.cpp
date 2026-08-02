#include <QDnsLookup>

#include "dns_check_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h".h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"

#include "acme_object.h"

#include "js_http.h"

DNSCheckDlg::DNSCheckDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &pub_key_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mHTTP01Btn, SIGNAL(clicked()), this, SLOT(clickHTTP01()));
    connect( mDNS01Btn, SIGNAL(clicked()), this, SLOT(clickDNS01()));
    connect( mTLS_ALPN01Btn, SIGNAL(clicked()), this, SLOT(clickTLS_ALPN01()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

DNSCheckDlg::~DNSCheckDlg()
{
    JS_BIN_reset( &pub_key_ );
}

void DNSCheckDlg::initUI()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();
    mDNSCombo->setEditable( true );
}

void DNSCheckDlg::initialize()
{
    mUseCertManCheck->setChecked( berApplet->settingsMgr()->useCertMan() );
}

void DNSCheckDlg::addDNS( const QString strDNS )
{
    mDNSCombo->addItem( strDNS );
}

void DNSCheckDlg::setPubKey( const BIN *pPubKey )
{
    JS_BIN_reset( &pub_key_ );
    JS_BIN_copy( &pub_key_, pPubKey );
}

void DNSCheckDlg::setToken( const QString strToken )
{
    mTokenText->setText( strToken );
}

int DNSCheckDlg::checkHTTP01( const QString strDNS, const QString strToken, const BIN *pPub )
{
    int ret = 0;
    int status = 0;
    char *pRsp = NULL;

    QString strKeyAuth;
    QString strURL;
    QString strThumbPrint = ACMEObject::getThumbPrint( pPub );

    strURL = QString( "http://%1/.well-known/acme-challenge/%2" ).arg( strDNS ).arg( strToken );
    strKeyAuth = QString("%1.%2").arg( strToken ).arg( strThumbPrint );

    berApplet->log( QString( "keyAuthorization: %1").arg( strKeyAuth ));

    ret = JS_HTTP_requestGet( strURL.toStdString().c_str(), &status, &pRsp );
    if( ret != JSR_OK ) return ret;

    if( strKeyAuth.compare( QString("%1").arg(pRsp), Qt::CaseInsensitive ) != 0 )
        return JSR_ERR;

    return JSR_OK;
}

int DNSCheckDlg::checkDNS01( const QString strDNS, const QString strToken, const BIN *pPub )
{
    QString strKeyAuth;
    QDnsLookup dns;
    QString strURL;

    QString strThumbPrint = ACMEObject::getThumbPrint( pPub );
    strKeyAuth = QString("%1.%2").arg( strToken ).arg( strThumbPrint );

    strURL = QString( "_acme-challenge.%1").arg( strDNS );
    dns.setType(QDnsLookup::TXT);
    dns.setName( strURL );
    dns.lookup();

    QList<QDnsTextRecord> dnsList = dns.textRecords();

    for( int i = 0; i < dnsList.size(); i++ )
    {
        if( strDNS == dnsList.at(i).name() )
        {
            return JSR_OK;
        }
    }

    berApplet->log( QString( "keyAuthorization: %1").arg( strKeyAuth ));

    return JSR_ERR;
}

int DNSCheckDlg::checkTLS_ALPN01( const QString strDNS, const QString strCID, const BIN *pPub )
{
    return 0;
}

void DNSCheckDlg::clickHTTP01()
{
    QString strDNS = mDNSCombo->currentText();
    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS"), this );
        mDNSCombo->setFocus();
        return;
    }

    QString strToken = mTokenText->text();
    if( strToken.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a Token"), this );
        mTokenText->setFocus();
        return;
    }

    if( pub_key_.nLen > 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            CertManDlg certMan;

            certMan.setMode( ManModeSelCert );
            certMan.setTitle( tr( "Select a certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return;

            certMan.getCert( &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, &pub_key_ );
            JS_BIN_reset( &binCert );
        }
        else
        {
            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return;

            QString strPubPath = keyPairMan.getPubPath();

            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &pub_key_ );
        }
    }

    int ret = checkHTTP01( strDNS, strToken, &pub_key_ );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DNS check OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to check DNS: %1").arg(ret), this );
    }
}

void DNSCheckDlg::clickDNS01()
{
    QString strDNS = mDNSCombo->currentText();
    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS"), this );
        mDNSCombo->setFocus();
        return;
    }

    QString strToken = mTokenText->text();
    if( strToken.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a Token"), this );
        mTokenText->setFocus();
        return;
    }

    if( pub_key_.nLen > 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            CertManDlg certMan;

            certMan.setMode( ManModeSelCert );
            certMan.setTitle( tr( "Select a certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return;

            certMan.getCert( &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, &pub_key_ );
            JS_BIN_reset( &binCert );
        }
        else
        {
            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return;

            QString strPubPath = keyPairMan.getPubPath();

            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &pub_key_ );
        }
    }

    int ret = checkDNS01( strDNS, strToken, &pub_key_ );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DNS check OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to check DNS: %1").arg(ret), this );
    }
}

void DNSCheckDlg::clickTLS_ALPN01()
{
    QString strDNS = mDNSCombo->currentText();
    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS"), this );
        mDNSCombo->setFocus();
        return;
    }

    QString strToken = mTokenText->text();
    if( strToken.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a Token"), this );
        mTokenText->setFocus();
        return;
    }

    if( pub_key_.nLen > 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            CertManDlg certMan;

            certMan.setMode( ManModeSelCert );
            certMan.setTitle( tr( "Select a certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return;

            certMan.getCert( &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, &pub_key_ );
            JS_BIN_reset( &binCert );
        }
        else
        {
            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return;

            QString strPubPath = keyPairMan.getPubPath();

            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &pub_key_ );
        }
    }

    int ret = checkTLS_ALPN01( strDNS, strToken, &pub_key_ );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DNS check OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to check DNS: %1").arg(ret), this );
    }
}
