#include "insert_ttlv_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"


InsertTTLVDlg::InsertTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));

    initialize();
}

InsertTTLVDlg::~InsertTTLVDlg()
{

}

void InsertTTLVDlg::initialize()
{
    mHexRadio->setChecked(true);
}

void InsertTTLVDlg::clickView()
{
    int nType = 0;
    BIN binData = {0,0};

    if( mHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strData = mDataText->toPlainText();

    if( strData.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter your data"), this );
        mDataText->setFocus();
        return;
    }

    getBINFromString( &binData, nType, strData );
    berApplet->decodeTTLV( &binData );

    JS_BIN_reset( &binData );
    QDialog::accept();
}

void InsertTTLVDlg::changeData()
{
    int nType = 0;

    if( mHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(nLen));
}
