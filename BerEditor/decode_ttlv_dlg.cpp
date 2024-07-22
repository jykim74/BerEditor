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

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(findData()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clearData()));

    initialize();
    mViewBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize( minimumSizeHint().width(), minimumSizeHint().height());
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
    if( binData.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is an invalid character" ), this);
        mDataText->setFocus();
        return;
    }

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

    QString strLen = getDataLenString( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void DecodeTTLVDlg::clearData()
{
    mDataText->clear();
}

void DecodeTTLVDlg::findData()
{
    BIN binData = {0,0};
    QString strPath = berApplet->curFolder();

    QString strFileName = findFile( this, JS_FILE_TYPE_BIN, strPath );
    if( strFileName.length() < 1 ) return;

    JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binData );
    if( mHexRadio->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else
    {
        char *pBase64 = NULL;
        JS_BIN_encodeBase64( &binData, &pBase64 );

        if( pBase64 )
        {
            mDataText->setPlainText( pBase64 );
            JS_free( pBase64 );
        }
    }

    JS_BIN_reset( &binData );
    berApplet->setCurFile( strFileName );
}

