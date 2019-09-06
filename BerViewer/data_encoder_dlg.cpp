#include "data_encoder_dlg.h"
#include "ui_data_encoder_dlg.h"

DataEncoderDlg::DataEncoderDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DataEncoderDlg)
{
    ui->setupUi(this);
}

DataEncoderDlg::~DataEncoderDlg()
{
    delete ui;
}
