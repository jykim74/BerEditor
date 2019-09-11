#include "sign_verify_dlg.h"
#include "ui_sign_verify_dlg.h"

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SignVerifyDlg)
{
    ui->setupUi(this);
}

SignVerifyDlg::~SignVerifyDlg()
{
    delete ui;
}
