#include <QSettings>

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

    initUI();
}

GetURIDlg::~GetURIDlg()
{
    JS_BIN_reset( &data_ );
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
            return;
        }

        QString strURI = getValidURL();
        berApplet->log( QString( "Get Address: %1").arg( strURI ));

        QStringList strList = strURI.split( ":" );
        if( strList.size() < 2 )
        {
            ret = -1;
            goto end;
        }

        QString strProto = strList.at(0);

        if( strProto == "ldap" )
            ret = getLDAP();
        else if( strProto == "http" || strProto == "https" )
            ret = getHTTP();
        else
        {
            berApplet->elog( QString("Invalid Protocol : %1").arg( strProto));
            ret = -1;
        }
    }

end :

    if( ret == 0 )
    {
        berApplet->decodeData( &data_, "Unknown" );
        QDialog::accept();
    }
    else
        QDialog::reject();
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

    mCloseBtn->setFocus();
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

const QString GetURIDlg::getValidURL()
{
    QString strURL = mURICombo->currentText();

    strURL.remove( "url=" );
    strURL.remove( "uri=" );
    strURL.remove( "URL=" );
    strURL.remove( "URI=" );

    return strURL.simplified();
}
