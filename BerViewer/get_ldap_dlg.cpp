#include "get_ldap_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"

static QStringList sScopeList = { "BASE" };
static QStringList sTypeList = { "caCertificate", "signCertificate", "userCertificate",
                               "certificateRevocationList", "autorithRevocationList",
                               "deltaRevocationList", "certificateTrustList"
};

GetLdapDlg::GetLdapDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

GetLdapDlg::~GetLdapDlg()
{

}

void GetLdapDlg::initUI()
{
    mScopeCombo->addItems(sScopeList);
    mTypeCombo->addItems(sTypeList);
}
