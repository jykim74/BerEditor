#include "insert_data_dlg.h"
#include "ber_applet.h"

InsertDataDlg::InsertDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(viewData()));

    mTypeHex->setChecked(true);
}

InsertDataDlg::~InsertDataDlg()
{

}

void InsertDataDlg::viewData()
{
    if( mTypeHex->isChecked() )
        type_ = 0;
    else if( mTypeBase64->isChecked() )
        type_ = 1;

    if( mTextData->toPlainText().isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
    }

    QDialog::accept();
}


QString InsertDataDlg::getTextData()
{
    return mTextData->toPlainText();
}
