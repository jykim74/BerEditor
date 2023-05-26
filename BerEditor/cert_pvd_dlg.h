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
    void clickTrustFind();
    void clickUntrustFind();
    void clickCRLFind();
    void clickTargetFind();

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

private:
    void initialize();
    QString last_path_;

};

#endif // CERT_PVD_DLG_H
