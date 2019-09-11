#include "rsa_enc_dec_dlg.h"
#include "ui_rsa_enc_dec_dlg.h"

RSAEncDecDlg::RSAEncDecDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RSAEncDecDlg)
{
    ui->setupUi(this);
}

RSAEncDecDlg::~RSAEncDecDlg()
{
    delete ui;
}
