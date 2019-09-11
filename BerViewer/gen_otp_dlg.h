#ifndef GEN_OTP_DLG_H
#define GEN_OTP_DLG_H

#include <QDialog>

namespace Ui {
class GenOTPDlg;
}

class GenOTPDlg : public QDialog
{
    Q_OBJECT

public:
    explicit GenOTPDlg(QWidget *parent = nullptr);
    ~GenOTPDlg();

private:
    Ui::GenOTPDlg *ui;
};

#endif // GEN_OTP_DLG_H
