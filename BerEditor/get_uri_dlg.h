#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>
#include "ui_get_uri_dlg.h"
#include "js_bin.h"

namespace Ui {
class GetURIDlg;
}

class GetURIDlg : public QDialog, public Ui::GetURIDlg
{
    Q_OBJECT

public:
    explicit GetURIDlg(QWidget *parent = nullptr);
    ~GetURIDlg();
    BIN& getData() { return data_; };

private slots:
    void runGet();
    void clickUseLDAPHost();
    void clickClearUsedURI();

private:
    void initUI();
    QStringList getUsedURI();
    void saveUsedURI( const QString &strURL );

    int getLDAP();
    int getHTTP();

    BIN data_;
};

#endif // GET_LDAP_DLG_H
