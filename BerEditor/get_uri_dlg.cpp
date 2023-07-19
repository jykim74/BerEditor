#include <QSettings>

#include "get_uri_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"

#include "js_ldap.h"
#include "js_bin.h"
#include "js_http.h"

const char *kUsedURI = "UsedURI";
const char *kLDAP = "LDAP";

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

    settings.beginGroup( kUsedURI );
    retList = settings.value( kLDAP ).toStringList();
    settings.endGroup();

    return retList;
}

void GetURIDlg::saveUsedURI( const QString &strURL )
{

    QSettings settings;
    settings.beginGroup( kUsedURI );
    QStringList list = settings.value( kLDAP ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kLDAP, list );
    settings.endGroup();
}

void GetURIDlg::runGet()
{
    int ret = -1;
    if( mUseLDAPHostCheck->isChecked() )
    {
        ret = getLDAP();
    }
    else
    {
        QString strURI = mURICombo->currentText();
        QStringList strList = strURI.split( ":" );
        if( strList.size() < 2 )
        {
            ret = -1;
            goto end;
        }

        QString strProto = strList.at(0).toUpper();

        if( strProto == "LDAP" )
            ret = getLDAP();
        else if( strProto == "HTTP" || strProto == "HTTPS" )
            ret = getHTTP();
        else
        {
            berApplet->elog( QString("Invalid Protocol : %1").arg( strProto));
            ret = -1;
        }
    }

end :

    if( ret == 0 ) QDialog::accept();
}

int GetURIDlg::getLDAP()
{
    int ret = -1;
    LDAP *pLD = NULL;

    int nPort = -1;
    QString strFilter = "(objectClass=*)";
    int nScope = LDAP_SCOPE_BASE;
    int nType = -1;
    QString strDN = "";
    QString strHost = "";


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

        QString strURI = mURICombo->currentText();

        ret = JS_LDAP_parseURI( strURI.toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        if( sHost[0] != 0x00 ) strHost = sHost;
        if( sDN[0] != 0x00 ) strDN = sDN;
        if( sFilter[0] != 0 ) strFilter = sFilter;


        saveUsedURI( strURI );
    }

    if( nType < 0 ) nType = JS_LDAP_getType( mTypeCombo->currentText().toStdString().c_str() );
    if( nScope < 0 ) nScope = LDAP_SCOPE_BASE;
    if( strFilter.length() < 1 ) strFilter = "(objectClass=*)";

    pLD = JS_LDAP_init( strHost.toStdString().c_str(), nPort );
    if( pLD == NULL )
    {
        berApplet->warningBox( tr("fail to connnect LDAP server" ), this );
        return -1;
    }

    ret = JS_LDAP_bind( pLD, NULL, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("fail to bind LDAP server"), this );
        goto end;
    }

    ret = JS_LDAP_getData( pLD, strDN.toStdString().c_str(), strFilter.toStdString().c_str(), nType, nScope, &data_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to get data from LDAP server"), this );
        goto end;
    }

end :
    if( pLD ) JS_LDAP_close(pLD);
    return ret;
}

int GetURIDlg::getHTTP()
{
    int ret = 0;
    int nStatus = 0;

    QString strURI = mURICombo->currentText();

    ret = JS_HTTP_requestGetBin2( strURI.toStdString().c_str(), NULL, NULL, &nStatus, &data_ );

     saveUsedURI( strURI );

    return ret;
}

void GetURIDlg::initUI()
{
    mScopeCombo->addItems(sScopeList);
    mTypeCombo->addItems(sTypeList);
    mPortText->setText( "389" );

    clickUseLDAPHost();
    mCloseBtn->setFocus();
}

void GetURIDlg::clickUseLDAPHost()
{
    bool bVal = mUseLDAPHostCheck->isChecked();

    mURIGroup->setEnabled( !bVal );
    mURICombo->setEditable( !bVal );

    if( !bVal )
    {
        mURICombo->addItems( getUsedURI() );
        mURICombo->clearEditText();
    }

    mHostInfoGroup->setEnabled( bVal );


    /*
    mURIText->setEnabled( bVal );
    mHostText->setEnabled( !bVal );
    mPortText->setEnabled( !bVal );
    mFilterText->setEnabled( !bVal );
    mScopeCombo->setEnabled( !bVal );
    mDNText->setEnabled( !bVal );
    mTypeCombo->setEnabled( !bVal );
    */
}

void GetURIDlg::clickClearUsedURI()
{
    QSettings settings;
    settings.beginGroup( kUsedURI );
    settings.setValue( kLDAP, "" );
    settings.endGroup();

    berApplet->log( "clear used URIs" );
}
