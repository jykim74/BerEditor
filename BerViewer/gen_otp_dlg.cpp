#include "gen_otp_dlg.h"
#include "ui_gen_otp_dlg.h"

GenOTPDlg::GenOTPDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::GenOTPDlg)
{
    ui->setupUi(this);
}

GenOTPDlg::~GenOTPDlg()
{
    delete ui;
}
