#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>
#include "ui_get_ldap_dlg.h"

namespace Ui {
class GetLdapDlg;
}

class GetLdapDlg : public QDialog, public Ui::GetLdapDlg
{
    Q_OBJECT

public:
    explicit GetLdapDlg(QWidget *parent = nullptr);
    ~GetLdapDlg();

private:
    void initUI();
};

#endif // GET_LDAP_DLG_H
