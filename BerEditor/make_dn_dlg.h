/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAKE_DN_DLG_H
#define MAKE_DN_DLG_H

#include <QDialog>
#include "ui_make_dn_dlg.h"

namespace Ui {
class MakeDNDlg;
}

class MakeDNDlg : public QDialog, public Ui::MakeDNDlg
{
    Q_OBJECT

public:
    explicit MakeDNDlg(QWidget *parent = nullptr);
    ~MakeDNDlg();
    void setDN( const QString strDN );
    const QString getDN();

private slots:
    void slotTableMenuRequested( QPoint pos );

    void clickOK();
    void clickClear();
    void changeDN();
    void clickRDNAdd();
    void deleteRDN();

private:
    void initUI();
    void initialize();
    void appendRDNTable( const QString strName, const QString strValue );
};

#endif // MAKE_DN_DLG_H
