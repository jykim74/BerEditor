#include "about_dlg.h"
#include "ui_about_dlg.h"

AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDlg)
{
    ui->setupUi(this);
}

AboutDlg::~AboutDlg()
{
    delete ui;
}
