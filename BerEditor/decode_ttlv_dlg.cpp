#include "decode_ttlv_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"


DecodeTTLVDlg::DecodeTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));

    initialize();
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

DecodeTTLVDlg::~DecodeTTLVDlg()
{

}

void DecodeTTLVDlg::initialize()
{
    mHexRadio->setChecked(true);
}

void DecodeTTLVDlg::clickView()
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

void DecodeTTLVDlg::changeData()
{
    int nType = 0;

    if( mHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(nLen));
}
