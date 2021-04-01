#include "insert_data_dlg.h"
#include "ber_applet.h"
#include "common.h"

InsertDataDlg::InsertDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(viewData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
    connect( mTypeHex, SIGNAL(clicked()), this, SLOT(dataChanged()));
    connect( mTypeBase64, SIGNAL(clicked()), this, SLOT(dataChanged()));

    mTypeHex->setChecked(true);
    mCloseBtn->setFocus();
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

    if( mDataText->toPlainText().isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
    }

    QDialog::accept();
}


QString InsertDataDlg::getTextData()
{
    return mDataText->toPlainText();
}

void InsertDataDlg::dataChanged()
{
    int nType = 0;

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(nLen));
}
