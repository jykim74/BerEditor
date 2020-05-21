#include "get_ldap_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"

#include "js_ldap.h"
#include "js_bin.h"

static QStringList sScopeList = { "BASE" };
static QStringList sTypeList = { "caCertificate", "signCertificate", "userCertificate",
                               "certificateRevocationList", "autorithRevocationList",
                               "deltaRevocationList", "certificateTrustList"
};

GetLdapDlg::GetLdapDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    data_.nLen = 0;
    data_.pVal = 0;

    connect( mURIUseCheck, SIGNAL(clicked()), this, SLOT(clickUseURI()));
    initUI();
}

GetLdapDlg::~GetLdapDlg()
{
    JS_BIN_reset( &data_ );
}

void GetLdapDlg::accept()
{
    int ret = -1;
    int nType = -1;
    LDAP *pLD = NULL;


    if( mURIUseCheck->isChecked() )
    {
        char    sHost[1024];
        char    sDN[1024];
        int     nPort = -1;
        int     nScope = -1;
        char    sFilter[256];
        char    sAttribute[256];

        QString strURI = mURIText->text();

        ret = JS_LDAP_parseURI( strURI.toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        pLD = JS_LDAP_init( sHost, nPort );
        if( pLD == NULL ) return;

        ret = JS_LDAP_bind( pLD, NULL, NULL );
        ret = JS_LDAP_getData( pLD, sDN, sFilter, nType, nScope, &data_ );
    }
    else {
        nType = JS_LDAP_getType( mTypeCombo->currentText().toStdString().c_str() );
        pLD = JS_LDAP_init( mHostText->text().toStdString().c_str(), mPortText->text().toInt());
        if( pLD == NULL ) return;

        ret = JS_LDAP_bind( pLD, NULL, NULL );
        ret = JS_LDAP_getData( pLD,
                               mDNText->text().toStdString().c_str(),
                               mFilterText->text().toStdString().c_str(),
                               nType,
                               LDAP_SCOPE_BASE,
                               &data_ );
    }

    if( pLD ) JS_LDAP_close(pLD);

    if( ret == 0 ) QDialog::accept();
}

void GetLdapDlg::initUI()
{
    mScopeCombo->addItems(sScopeList);
    mTypeCombo->addItems(sTypeList);
    mPortText->setText( "389" );

    clickUseURI();
}

void GetLdapDlg::clickUseURI()
{
    bool bVal = mURIUseCheck->isChecked();

    mURIGroup->setEnabled( bVal );
    mHostInfoGroup->setEnabled( !bVal );

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
