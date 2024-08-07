/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_OTP_DLG_H
#define GEN_OTP_DLG_H

#include <QDialog>
#include "ui_gen_otp_dlg.h"

namespace Ui {
class GenOTPDlg;
}

class GenOTPDlg : public QDialog, public Ui::GenOTPDlg
{
    Q_OBJECT

public:
    explicit GenOTPDlg(QWidget *parent = nullptr);
    ~GenOTPDlg();

private slots:
    void setNow();
    void clickGenOTP();
    void keyChanged();

    void clickClearDataAll();
    void changeDateTime( QDateTime dateTime );

private:
    void initialize();

};

#endif // GEN_OTP_DLG_H
