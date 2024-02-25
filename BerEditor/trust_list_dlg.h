/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef TRUST_LIST_DLG_H
#define TRUST_LIST_DLG_H

#include <QDialog>
#include "ui_trust_list_dlg.h"

namespace Ui {
class TrustListDlg;
}

class TrustListDlg : public QDialog, public Ui::TrustListDlg
{
    Q_OBJECT

public:
    explicit TrustListDlg(QWidget *parent = nullptr);
    ~TrustListDlg();

private slots:
    void clickAdd();
    void clickDelete();
    void viewCert();
    void slotTableListMenuRequested( QPoint pos );


private:
    void initialize();
    void loadList();
    void clearList();
};

#endif // TRUST_LIST_DLG_H
