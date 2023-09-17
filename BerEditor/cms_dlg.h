#ifndef CMS_DLG_H
#define CMS_DLG_H

#include <QDialog>
#include "ui_cms_dlg.h"
#include "js_bin.h"

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

    void clickSignPriKeyType();
    void clickSignCertType();
    void clickKMPriKeyType();
    void clickKMCertType();

    void srcChanged();
    void outputChanged();

    void clickClearDataAll();
    void clickReadFile();

    void checkSignEncPriKey();
    void checkKMEncPriKey();

private:
    void initialize();
    int readSignPrivateKey( BIN *pPriKey );
    int readKMPrivateKey( BIN *pPriKey );

    QString last_path_;
    QButtonGroup* group_;

};

#endif // CMS_DLG_H
