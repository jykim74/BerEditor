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
    void findPrivateKey();
    void findPublicKey();
    virtual void accept();

private:
    void initialize();
};

#endif // SIGN_VERIFY_DLG_H
