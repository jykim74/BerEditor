#include "insert_data_dlg.h"
//#include "ui_insert_data_dlg.h"

InsertDataDlg::InsertDataDlg(QWidget *parent) :
    QDialog(parent)
//    ui(new Ui::InsertDataDlg)
{
//    ui->setupUi(this);
    setupUi(this);

    mTypeHex->setChecked(true);
}

InsertDataDlg::~InsertDataDlg()
{
//    delete ui;
}

void InsertDataDlg::accept()
{
    if( mTypeHex->isChecked() )
        type_ = 0;
    else if( mTypeBase64->isChecked() )
        type_ = 1;

    QDialog::accept();
}


QString InsertDataDlg::getTextData()
{
    return mTextData->toPlainText();
}
