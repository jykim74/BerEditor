#ifndef CMS_DLG_H
#define CMS_DLG_H

#include <QDialog>
#include "ui_cms_dlg.h"

namespace Ui {
class CMSDlg;
}

class CMSDlg : public QDialog, public Ui::CMSDlg
{
    Q_OBJECT

public:
    explicit CMSDlg(QWidget *parent = nullptr);
    ~CMSDlg();

private slots:
    void clickClose();
    void clickDecode();
    void clickChange();
    void clickSignPriFind();
    void clickSignCertFind();
    void clickKMPriFind();
    void clickKMCertFind();
    void clickSignedData();
    void clickEnvelopedData();
    void clickSignAndEnvloped();
    void clickVerifyData();
    void clickDevelopedData();
    void clickDevelopedAndVerify();

    void clickSignPriKeyDecode();
    void clickSignCertView();
    void clickSignCertDecode();
    void clickKMPriKeyDecode();
    void clickKMCertView();
    void clickKMCertDecode();

    void srcChanged();
    void outputChanged();

    void clickClearDataAll();

private:
    void initialize();
    QString last_path_;
    QButtonGroup* group_;

};

#endif // CMS_DLG_H
