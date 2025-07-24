/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

    void setCA( const QString strURL );
    void setCRL( const QString strURL );

private slots:
    void runGet();
    void clickUseLDAPHost();
    void clickClearUsedURI();
    void changeURL();

private:
    void initUI();
    QStringList getUsedURI();
    void saveUsedURI( const QString &strURL );

    int getLDAP();
    int getHTTP();

    const QString getValidURL();

    void setEnvLdapHost( const QString strHost );
    void setEnvLdapPort( int nPort );
    const QString getEnvLdapHost();
    int getEnvLdapPort();

    BIN data_;
};

#endif // GET_LDAP_DLG_H
