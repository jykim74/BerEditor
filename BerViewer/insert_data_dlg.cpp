#include "insert_data_dlg.h"
#include "ui_insert_data_dlg.h"

InsertDataDlg::InsertDataDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InsertDataDlg)
{
    ui->setupUi(this);
}

InsertDataDlg::~InsertDataDlg()
{
    delete ui;
}
