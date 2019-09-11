#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EncDecDlg)
{
    ui->setupUi(this);
}

EncDecDlg::~EncDecDlg()
{
    delete ui;
}
