#include "gen_hmac_dlg.h"
#include "ui_gen_hmac_dlg.h"

GenHmacDlg::GenHmacDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::GenHmacDlg)
{
    ui->setupUi(this);
}

GenHmacDlg::~GenHmacDlg()
{
    delete ui;
}
