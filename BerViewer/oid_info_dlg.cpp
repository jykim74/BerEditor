#include "oid_info_dlg.h"
#include "ui_oid_info_dlg.h"

OIDInfoDlg::OIDInfoDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OIDInfoDlg)
{
    ui->setupUi(this);
}

OIDInfoDlg::~OIDInfoDlg()
{
    delete ui;
}
