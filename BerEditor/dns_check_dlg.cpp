#include <QDnsLookup>

#include "dns_check_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h".h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "cert_info_dlg.h"
#include "export_dlg.h"
#include "new_passwd_dlg.h"

#include "acme_object.h"

#include "js_pki_key.h"
#include "js_pki.h"
#include "js_http.h"
#include "js_net.h"
#include "js_ssl.h"
#include "js_pki_ext.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"

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
    connect( mMakeSelfCertBtn, SIGNAL(clicked()), this, SLOT(clickMakeSelfSignCert()));

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
    mHashCombo->addItems( kSHA12HashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );
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
    int ret = 0;
    int nSockFd = JS_NET_connectTimeout( strDNS.toStdString().c_str(), 443, 5 );

    ret = JS_SSL_ALPNClient( nSockFd, strDNS.toStdString().c_str() );

    return ret;
}

void DNSCheckDlg::clickHTTP01()
{
    checkDNS( ACME_HTTP_01 );
}

void DNSCheckDlg::clickDNS01()
{
    checkDNS( ACME_DNS_01 );
}

void DNSCheckDlg::clickTLS_ALPN01()
{
    checkDNS( ACME_TLS_ALPN_01 );
}

void DNSCheckDlg::checkDNS( ACME_CheckType type )
{
    int ret = 0;
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

    if( pub_key_.nLen <= 0 )
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

    if( type == ACME_HTTP_01 )
        ret = checkHTTP01( strDNS, strToken, &pub_key_ );
    else if( type == ACME_DNS_01 )
        ret = checkDNS01( strDNS, strToken, &pub_key_ );
    else if( type == ACME_TLS_ALPN_01 )
        ret = checkTLS_ALPN01( strDNS, strToken, &pub_key_ );
    else
    {
        ret = JSR_INVALID;
    }

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DNS check OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to check DNS: %1").arg(ret), this );
    }
}

void DNSCheckDlg::clickMakeSelfSignCert()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binAuth = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};

    int nParam = -1;
    int nKeyType = -1;

    QString strDNS = mDNSCombo->currentText();
    QString strHash = mHashCombo->currentText();
    QString strDN = mDNText->text();
    QString strSerial = mSerialText->text();
    QString strToken = mTokenText->text();

    CertInfoDlg certInfo;

    if( strToken.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a Token" ), this );
        mTokenText->setFocus();
        return;
    }

    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a DNS" ), this );
        mDNSCombo->setFocus();
        return;
    }

    if( strSerial.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a serial" ), this );
        mSerialText->setFocus();
        return;
    }

    if( strDN.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DN" ), this );
        mDNText->setFocus();
        return;
    }

    if( pub_key_.nLen <= 0 )
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

    QString strThumbPrint = ACMEObject::getThumbPrint( &pub_key_ );
    QString strSrc = QString( "%1.%2" ).arg( strThumbPrint ).arg( strToken );
    JS_BIN_set( &binSrc, (unsigned char *)strSrc.toStdString().c_str(), strSrc.length() );

    JS_PKI_getPubKeyInfo( &pub_key_, &nKeyType, &nParam );
    JS_PKI_genHash( "SHA256", &binSrc, &binAuth );

    if( nKeyType < 0 )
    {
        nKeyType = JS_PKI_KEY_TYPE_RSA;
        nParam = 2048;
    }

    ret = JS_PKI_genKeyPair( nKeyType, nParam, 65537, &binPub, &binPri );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to generate keypair: %1").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_makeALPNSelfSignCert(
        strHash.toStdString().c_str(),
        strSerial.toStdString().c_str(),
        strDN.toStdString().c_str(),
        &binPri,
        strDNS.toStdString().c_str(),
        &binAuth,
        &binCert );

    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to make self signed certificate:%1").arg(ret), this);
        goto end;
    }

    savePriKeyCert( &binPri, &binCert );

    certInfo.setCertBIN( &binCert );
    certInfo.exec();

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrc );
}

int DNSCheckDlg::savePriKeyCert( const BIN *pPriKey, const BIN *pCert )
{
    int ret = 0;

    bool bVal = false;
    bVal = berApplet->yesOrNoBox( tr( "Do you want to save the private key and certificate"), this, true );
    if( bVal == true )
    {
        int nKeyType = -1;
        BIN binEncPri = {0,0};
        CertManDlg certMan;
        NewPasswdDlg newPass;
        int nPBE = -1;
        nPBE = JS_PKI_getNidFromSN( berApplet->settingsMgr()->priEncMethod().toStdString().c_str() );

        if( newPass.exec() == QDialog::Accepted )
        {
            QString strPass = newPass.mPasswdText->text();
            nKeyType = JS_PKI_getPriKeyType( pPriKey );

            ret = JS_PKI_encryptPrivateKey( nPBE, strPass.toStdString().c_str(), pPriKey, NULL, &binEncPri );
            if( ret == 0 )
            {
                ret = certMan.writePriKeyCert( &binEncPri, pCert );
                if( ret == 0 )
                    berApplet->messageLog( tr( "The private key and certificate are saved successfully" ), this );
                else
                    berApplet->warnLog( tr( "failed to save the private key and certificate" ), this );
            }
        }

        JS_BIN_reset( &binEncPri );
    }

    return ret;
}
