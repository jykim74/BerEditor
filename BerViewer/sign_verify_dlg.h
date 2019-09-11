#ifndef SIGN_VERIFY_DLG_H
#define SIGN_VERIFY_DLG_H

#include <QDialog>

namespace Ui {
class SignVerifyDlg;
}

class SignVerifyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit SignVerifyDlg(QWidget *parent = nullptr);
    ~SignVerifyDlg();

private:
    Ui::SignVerifyDlg *ui;
};

#endif // SIGN_VERIFY_DLG_H
