/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_PVD_DLG_H
#define CERT_PVD_DLG_H

#include <QDialog>
#include "ui_cert_pvd_dlg.h"

namespace Ui {
class CertPVDDlg;
}

class CertPVDDlg : public QDialog, public Ui::CertPVDDlg
{
    Q_OBJECT

public:
    explicit CertPVDDlg(QWidget *parent = nullptr);
    ~CertPVDDlg();

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void slotPathMenu( QPoint pos );
    void slotParamMenu( QPoint pos );

    void delPath();
    void sendTarget();
    void delParam();

    void clickViewCertCRL();

    void clickTrustFind();
    void clickUntrustFind();
    void clickCRLFind();
    void clickTargetFind();

    void checkUseTrustList();
    void clickTrustList();

    void clickTrustInfo();
    void clickUntrustInfo();
    void clickCRLInfo();
    void clickTargetInfo();

    void clickTrustAdd();
    void clickUntrustAdd();
    void clickCRLAdd();

    void clickListClear();
    void clickPathClear();

    void checkATTime();

    void clickParamAdd();
    void clickParamListClear();

    void clickVerifyCert();
    void clickVerifyCRL();
    void clickPolicyCheck();
    void clickPathValidation();

    void clickTrustDecode();
    void clickUntrustDecode();
    void clickCRLDecode();
    void clickTargetDecode();

    void clickClearDataAll();
private:
    void initialize();
};

#endif // CERT_PVD_DLG_H
