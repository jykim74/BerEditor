#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>
#include "ui_get_ldap_dlg.h"
#include "js_bin.h"

namespace Ui {
class GetLdapDlg;
}

class GetLdapDlg : public QDialog, public Ui::GetLdapDlg
{
    Q_OBJECT

public:
    explicit GetLdapDlg(QWidget *parent = nullptr);
    ~GetLdapDlg();
    BIN& getData() { return data_; };

private slots:
    void runGet();
    void clickUseURI();

private:
    void initUI();
    QStringList getUsedURI();
    void saveUsedURI( const QString &strURL );

    BIN data_;
};

#endif // GET_LDAP_DLG_H
