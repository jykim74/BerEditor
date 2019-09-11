#include "gen_hash_dlg.h"
#include "ui_gen_hash_dlg.h"

GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::GenHashDlg)
{
    ui->setupUi(this);
}

GenHashDlg::~GenHashDlg()
{
    delete ui;
}
