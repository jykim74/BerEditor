#include <QDnsLookup>
#include <QSettings>

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
#include "js_dns.h"

const QString kDNSDefault = "DNSDefault";

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
    QString strDefault = getDefault();
    QStringList listDefault;

    if( strDefault.length() > 4 ) listDefault = strDefault.split(":");

    if( listDefault.size() >= 3 )
    {
        int nServerGroup = listDefault.at(0).toInt();
        QString strHost = listDefault.at(1);
        QString strPort = listDefault.at(2);

        mServerGroup->setChecked( nServerGroup );
        mHostText->setText( strHost );
        mPortText->setText( strPort );
    }

    mUseCertManCheck->setChecked( berApplet->settingsMgr()->useCertMan() );
}

QString DNSCheckDlg::getDefault()
{
    QSettings settings;
    QString strDefault;

    settings.beginGroup( kSettingBer );
    strDefault = settings.value( kDNSDefault ).toString();
    settings.endGroup();

    return strDefault;
}

void DNSCheckDlg::setDefault( const QString strDefault )
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kDNSDefault, strDefault );
    settings.endGroup();
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

    if( mServerGroup->isChecked() == true )
    {
        QString strHost = mHostText->text();
        int nPort = mPortText->text().toInt();
        if( nPort <= 0 ) nPort = 80;

        strURL = QString( "http://%1:%2/.well-known/acme-challenge/%3" ).arg( strHost ).arg( nPort ).arg( strToken );
    }
    else
    {
        strURL = QString( "http://%1/.well-known/acme-challenge/%2" ).arg( strDNS ).arg( strToken );
    }

    strKeyAuth = QString("%1.%2").arg( strToken ).arg( strThumbPrint );

    berApplet->log( QString( "keyAuthorization: %1").arg( strKeyAuth ));

    ret = JS_HTTP_requestGet( strURL.toStdString().c_str(), &status, &pRsp );
    if( ret != JSR_OK ) return ret;

    berApplet->log( QString( "Rsp: %1").arg( pRsp ));

    if( strKeyAuth.compare( QString("%1").arg(pRsp), Qt::CaseInsensitive ) != 0 )
    {
        ret = JSR_ERR;
        goto end;
    }

    ret = JSR_OK;

end :
    if( pRsp ) JS_free( pRsp );

    return ret;
}

int DNSCheckDlg::checkDNS01( const QString strDNS, const QString strToken, const BIN *pPub )
{
    int ret = JSR_ERR;
    QString strKeyAuth;

    QString strURL;
    BIN binSrc = {0,0};
    BIN binHash = {0,0};
    char *pAuthKey = NULL;

    QString strThumbPrint = ACMEObject::getThumbPrint( pPub );
    strKeyAuth = QString("%1.%2").arg( strToken ).arg( strThumbPrint );
    berApplet->log( QString( "keyAuthorization: %1").arg( strKeyAuth ));

    JS_BIN_set( &binSrc, (unsigned char *)strKeyAuth.toStdString().c_str(), strKeyAuth.length() );
    JS_PKI_genHash( "SHA256", &binSrc, &binHash );
    JS_BIN_encodeBase64URL( &binHash, &pAuthKey );

    QString strExpected = pAuthKey;
    strURL = QString( "_acme-challenge.%1.").arg( strDNS );

    if( mServerGroup->isChecked() == true )
    {
        QString strHost = mHostText->text();
        int nPort = mPortText->text().toInt();
        if( nPort <= 0 ) nPort = 53;

        BIN binQuery = {0,0};
        BIN binRsp = {0,0};
        int nType = -1;
        JStrList *pStrList = NULL;
        JStrList *pCurList = NULL;

        unsigned char packet[4096];

        memset( packet, 0x00, sizeof(packet));

        ret = JS_DNS_makeQuery( JS_DNS_TYPE_TXT, strDNS.toStdString().c_str(), &binQuery );

#if 0
        int nSockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if( nSockFd < 0 )
        {
            ret = JSR_ERR2;
            JS_BIN_reset( &binQuery );
            goto end;
        }

        ret = JS_NET_sendTo( nSockFd, strHost.toStdString().c_str(), nPort, binQuery.pVal, binQuery.nLen );
        if( ret < 0 )
        {
            ret = JSR_ERR3;
            JS_BIN_reset( &binQuery );
            goto end;
        }

        ret = JS_NET_recvFrom( nSockFd, strHost.toStdString().c_str(), nPort, packet, sizeof(packet) );
        if( ret < 0 )
        {
            ret = JSR_ERR4;
            JS_BIN_reset( &binQuery );
            goto end;
        }


        binRsp.pVal = packet;
        binRsp.nLen = sizeof(packet);
#else
        int nRetry = 3;
        int nTimeout = 5; //secs

        ret = JS_DNS_askQuery( strHost.toStdString().c_str(), nPort, &binQuery, nRetry, nTimeout, &binRsp );
        if( ret != JSR_OK )
        {
            goto end;
        }
#endif

        ret = JS_DNS_parseRsp( &binRsp, &nType, &pStrList );

        pCurList = pStrList;
        while( pCurList )
        {
            if( strExpected.compare( pCurList->pStr, Qt::CaseInsensitive ) == 0 )
            {
                ret = JSR_OK;
                break;
            }

            pCurList = pCurList->pNext;
        }

        if( pStrList ) JS_UTIL_resetStrList( &pStrList );
    }
    else
    {
        QDnsLookup dns;
        dns.setType(QDnsLookup::TXT);
        dns.setName( strURL );
        dns.lookup();

        QList<QDnsTextRecord> dnsList = dns.textRecords();

        for( int i = 0; i < dnsList.size(); i++ )
        {
            if( strExpected.compare( dnsList.at(i).name(), Qt::CaseInsensitive ) == 0 )
            {
                ret = JSR_OK;
                break;
            }
        }
    }


end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binHash );
    if( pAuthKey ) JS_free( pAuthKey );

    return ret;
}

int DNSCheckDlg::checkTLS_ALPN01( const QString strDNS, const QString strToken )
{
    int ret = 0;
    int nSockFd = -1;
    QString strKeyAuth;
    QString strURL;

    BIN binCert = {0,0};
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    JExtensionInfoList *pCurList = NULL;

    int bSelf = 0;
    const QString strAuthOID = "1.3.6.1.5.5.7.1.31";
    BIN binSrc = {0,0};
    BIN binAuth = {0,0};
    BIN binExt = {0,0};
    BIN binExtVal = {0,0};

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_BIN_set( &binSrc, (unsigned char *)strToken.toStdString().c_str(), strToken.length() );
    JS_PKI_genHash( "SHA256", &binSrc, &binAuth );

    if( mServerGroup->isChecked() == true )
    {
        QString strHost = mHostText->text();
        int nPort = mPortText->text().toInt();
        if( nPort <= 0 ) nPort = 443;

        nSockFd = JS_NET_connectTimeout( strHost.toStdString().c_str(), nPort, 5 );
    }
    else
    {
        nSockFd = JS_NET_connectTimeout( strDNS.toStdString().c_str(), 443, 5 );
    }

    ret = JS_SSL_ALPNClient( nSockFd, strDNS.toStdString().c_str(), &binCert );
    if( ret != 0 )
    {
        berApplet->elog( QString( "failed to run ALPNclient: %1" ).arg(ret));
        goto end;
    }

    if( mShowCertCheck->isChecked() == true )
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binCert );
        certInfo.exec();
    }

    ret = JS_PKI_getCertInfo2( &binCert, &sCertInfo, &pExtInfoList, &bSelf );
    if( ret != 0 )
    {
        berApplet->elog( QString( "failed to get self sign certificate info: %1" ).arg(ret));
        goto end;
    }

    pCurList = pExtInfoList;
    while( pCurList )
    {
        if( strAuthOID.compare( pCurList->sExtensionInfo.pOID, Qt::CaseInsensitive) == 0 )
        {
            JS_BIN_decodeHex( pCurList->sExtensionInfo.pValue, &binExt );
            char *pExt = NULL;
            JS_PKI_getOctetValue( &binExt, &pExt );

            if( pExt )
            {
                JS_BIN_decodeHex( pExt, &binExtVal );
                JS_free( pExt );
            }


            if( JS_BIN_cmp( &binAuth, &binExtVal ) == 0 )
            {
                ret = JSR_OK;
            }
            else
            {
                berApplet->elog( QString( "Auth Value is bad [%1 : %2]" )
                                    .arg( getHexString( &binAuth ))
                                    .arg( getHexString( &binExtVal )));

                ret = JSR_INVALID_VALUE;
            }

            break;
        }

        pCurList = pCurList->pNext;
    }

end :
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binExt );
    JS_BIN_reset( &binExtVal );
    if( nSockFd >= 0 ) JS_NET_close( nSockFd );

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

    QString strDefault;
    int nServerGroup = mServerGroup->isChecked();
    QString strHost = mHostText->text();
    QString strPort = mPortText->text();

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
        ret = checkTLS_ALPN01( strDNS, strToken );
    else
    {
        ret = JSR_INVALID;
    }

    strDefault = QString( "%1:%2:%3" ).arg( nServerGroup ).arg( strHost ).arg( strPort );
    setDefault( strDefault );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DNS check OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to check DNS: %1").arg(JERR(ret)), this );
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

    JS_BIN_set( &binSrc, (unsigned char *)strToken.toStdString().c_str(), strToken.length() );
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
