/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef OID_INFO_DLG_H
#define OID_INFO_DLG_H

#include <QDialog>
#include "ui_oid_info_dlg.h"

namespace Ui {
class OIDInfoDlg;
}

class OIDInfoDlg : public QDialog, public Ui::OIDInfoDlg
{
    Q_OBJECT

public:
    explicit OIDInfoDlg(QWidget *parent = nullptr);
    ~OIDInfoDlg();

private slots:
    virtual void accept();
    void findOID();
    void closeDlg();
    void createOID();

    void clickOutputClear();

private:
    void initialize();
    int writeOIDConfig( const QString& strMsg );

};

#endif // OID_INFO_DLG_H
