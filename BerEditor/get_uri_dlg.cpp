/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>
#include <QUrl>

#include "get_uri_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "common.h"
#include "js_ldap.h"
#include "js_bin.h"
#include "js_http.h"

const QString kGetUsedURL = "GetUsedURL";

static QStringList sScopeList = { "BASE" };
static QStringList sTypeList = { "caCertificate", "signCertificate", "userCertificate",
                               "certificateRevocationList", "autorithRevocationList",
                               "deltaRevocationList", "certificateTrustList"
};

GetURIDlg::GetURIDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    data_.nLen = 0;
    data_.pVal = 0;

    connect( mUseLDAPHostCheck, SIGNAL(clicked()), this, SLOT(clickUseLDAPHost()));
    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(runGet()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearUsedURIBtn, SIGNAL(clicked()), this, SLOT(clickClearUsedURI()));
    connect( mURICombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeURL()));

    initUI();
    mGetBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mLDAPSearchGroup->layout()->setSpacing(5);
    mLDAPSearchGroup->layout()->setMargin(5);

    mURIGroup->layout()->setSpacing(5);
    mURIGroup->layout()->setMargin(5);

    mHostInfoGroup->layout()->setSpacing(5);
    mHostInfoGroup->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GetURIDlg::~GetURIDlg()
{
    JS_BIN_reset( &data_ );
}

void GetURIDlg::setCA( const QString strURL )
{
    mURICombo->setCurrentText( strURL );
    mURICombo->setToolTip( strURL );
    mTypeCombo->setCurrentText( "caCertificate" );
}

void GetURIDlg::setCRL( const QString strURL )
{
    mURICombo->setCurrentText(strURL);
    mURICombo->setToolTip( strURL );
    mTypeCombo->setCurrentText( "certificateRevocationList" );
}

QStringList GetURIDlg::getUsedURI()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kGetUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void GetURIDlg::saveUsedURI( const QString &strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kGetUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kGetUsedURL, list );
    settings.endGroup();
}

void GetURIDlg::runGet()
{
    int ret = -1;

    if( mUseLDAPHostCheck->isChecked() )
    {
        QString strDN = mDNText->text();
        if( strDN.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a DN value" ), this );
            mDNText->setFocus();
            return;
        }

        ret = getLDAP();
    }
    else
    {
        QString strURL = mURICombo->currentText();
        if( strURL.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a URI value" ), this );
            mURICombo->setFocus();
            return;
        }

        QString strURI = getValidURL();
        QUrl url;
        url.setUrl( strURI );
        QString strScheme = url.scheme();

        if( strScheme.toLower() == "ldap" )
            ret = getLDAP();
        else if( strScheme.toLower() == "http" || strScheme.toLower() == "https" )
            ret = getHTTP();
        else
        {
            berApplet->warningBox( tr("Invalid Scheme : %1").arg( strScheme ), this );
            return;
        }
    }

end :

    if( ret == 0 )
    {
        berApplet->decodeData( &data_, "Unknown" );
        QDialog::accept();
    }
    else
    {
        berApplet->warnLog( tr( "failed to get data : %1").arg(ret), this);
    }
}

int GetURIDlg::getLDAP()
{
    int ret = -1;
    LDAP *pLD = NULL;

    int nPort = -1;
    QString strFilter;
    int nScope = LDAP_SCOPE_BASE;
    int nType = -1;
    QString strDN = "";
    QString strHost = "";
    QString strURI;


    if( mUseLDAPHostCheck->isChecked() )
    {
        strHost = mHostText->text();
        nPort = mPortText->text().toInt();
        strDN = mDNText->text();
        strFilter = mFilterText->text();
    }
    else {
        char    sHost[1024];
        char    sDN[1024];
        char    sFilter[256];
        char    sAttribute[256];

        memset( sHost, 0x00, sizeof(sHost));
        memset( sDN, 0x00, sizeof(sDN) );
        memset( sFilter, 0x00, sizeof(sFilter));
        memset( sAttribute, 0x00, sizeof(sAttribute));

        strURI = getValidURL();

        ret = JS_LDAP_parseURI( strURI.toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        if( sHost[0] != 0x00 ) strHost = sHost;
        if( sDN[0] != 0x00 ) strDN = sDN;
        if( sFilter[0] != 0 ) strFilter = sFilter;
        if( strFilter.length() < 1 ) strFilter = mFilterText->text();
    }

    if( nType < 0 ) nType = JS_LDAP_getType( mTypeCombo->currentText().toStdString().c_str() );
    if( nScope < 0 ) nScope = LDAP_SCOPE_BASE;


    pLD = JS_LDAP_init( strHost.toStdString().c_str(), nPort );
    if( pLD == NULL )
    {
        berApplet->warningBox( tr("failed to connnect LDAP server" ), this );
        return -1;
    }

    ret = JS_LDAP_bind( pLD, NULL, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to bind LDAP server"), this );
        goto end;
    }

    ret = JS_LDAP_getData( pLD, strDN.toStdString().c_str(), strFilter.toStdString().c_str(), nType, nScope, &data_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to get data from LDAP server"), this );
        goto end;
    }

    if( mUseLDAPHostCheck->isChecked() == false ) saveUsedURI( strURI );

end :
    if( pLD ) JS_LDAP_close(pLD);
    return ret;
}

int GetURIDlg::getHTTP()
{
    int ret = 0;
    int nStatus = 0;

    QString strURI = getValidURL();

    ret = JS_HTTP_requestGetBin2( strURI.toStdString().c_str(), NULL, NULL, &nStatus, &data_ );

    saveUsedURI( strURI );

    return ret;
}

void GetURIDlg::initUI()
{
    mScopeCombo->addItems(sScopeList);
    mTypeCombo->addItems(sTypeList);
    mHostText->setText( "127.0.0.1" );
    mPortText->setText( "389" );
    mFilterText->setText( "(objectClass=*)" );

    clickUseLDAPHost();
    mURICombo->addItems( getUsedURI() );
    mURICombo->setCurrentText( "" );

    mURILabel->setText( tr("ex) http://i.pki.goog/we2.crt") );
}

void GetURIDlg::clickUseLDAPHost()
{
    bool bVal = mUseLDAPHostCheck->isChecked();

    mURIGroup->setEnabled( !bVal );
    mURICombo->setEditable( !bVal );

    mHostInfoGroup->setEnabled( bVal );
}

void GetURIDlg::clickClearUsedURI()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kGetUsedURL, "" );
    settings.endGroup();

    mURICombo->clearEditText();
    mURICombo->clear();

    berApplet->log( "clear used URLs" );
}

void GetURIDlg::changeURL()
{
    QString strURL = mURICombo->currentText();
    mURICombo->setToolTip( strURL );
}

const QString GetURIDlg::getValidURL()
{
    QString strLink;
    QString strURL = mURICombo->currentText();

    QStringList strList = strURL.split( "=" );
    if( strList.size() < 1 )
        strLink.clear();
    else if( strList.size() == 1 )
        strLink = strList.at(0);
    else
    {
        if( strList.at(0).toUpper() == "URL" || strList.at(0).toUpper() == "URI" )
            strLink = strList.at(1);
    }

    return strLink.simplified();
}
