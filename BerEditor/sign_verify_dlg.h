#ifndef SIGN_VERIFY_DLG_H
#define SIGN_VERIFY_DLG_H

#include <QDialog>
#include "ui_sign_verify_dlg.h"

namespace Ui {
class SignVerifyDlg;
}

class SignVerifyDlg : public QDialog, public Ui::SignVerifyDlg
{
    Q_OBJECT

public:
    explicit SignVerifyDlg(QWidget *parent = nullptr);
    ~SignVerifyDlg();

private slots:
    void checkPubKeyVerify();
    void checkAutoCertOrPubKey();
    void clickCheckKeyPair();
    void findPrivateKey();
    void findCert();
    void algChanged(int index);
    void Run();
    void signVerifyInit();
    void signVerifyUpdate();
    void signVerifyFinal();

    void inputChanged();
    void outputChanged();
    void changeMethod( int index );

    void clickInputClear();
    void clickOutputClear();

    void clickPriKeyDecode();
    void clickCertView();
    void clickCertDecode();

    void clickPriKeyType();
    void clickCertType();

    void checkUseKeyAlg();
    void clickClearDataAll();

private:
    void initialize();
    void *sctx_;
    QString last_path_;
};

#endif // SIGN_VERIFY_DLG_H
