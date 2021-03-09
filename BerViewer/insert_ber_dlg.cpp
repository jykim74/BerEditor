#include "insert_ber_dlg.h"
#include "mainwindow.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"

const QStringList kClassList = { "Universal", "Application", "Content-Specific", "Private" };

InsertBerDlg::InsertBerDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mInsertBtn, SIGNAL(clicked()), this, SLOT(runInsert()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mConstructedCheck, SIGNAL(clicked()), this, SLOT(checkConstructed()));
    connect( mHeaderText, SIGNAL(textChanged(const QString&)), this, SLOT(headerChanged(const QString&)));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(valueChanged()));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mPrimitiveCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(primitiveChanged(int)));

    initialize();
    mCloseBtn->setFocus();
}

InsertBerDlg::~InsertBerDlg()
{

}

QString InsertBerDlg::getData()
{
    QString strData;

    strData = mHeaderText->text();
    strData += mValueText->toPlainText();

    return strData;
}

void InsertBerDlg::initialize()
{
    mClassCombo->addItems( kClassList );

    int nPrimitiveCnt = JS_BER_getPrimitiveCount();

    mPrimitiveCombo->addItem( "None" );

    for( int i = 0; i < nPrimitiveCnt; i++ )
    {
        const char *pName = JS_BER_getPrimitiveNameAt( i );
        mPrimitiveCombo->addItem( pName );
    }

    mPrimitiveCombo->setEditable( true );
}

void InsertBerDlg::makeHeader()
{
    unsigned char cTag = 0x00;
    unsigned char cPrimitive = 0x00;
    BIN binLen = {0,0};
    BIN binValue = {0,0};
    BIN binHeader = {0,0};
    char *pHex = NULL;
    char *pBitString = NULL;

    QString strClass = mClassCombo->currentText();

    if( strClass == "Universal" )
        cTag |= JS_UNIVERSAL;
    else if( strClass == "Application" )
        cTag |= JS_APPLICATION;
    else if( strClass == "Content-Specific" )
        cTag |= JS_CONTEXT;
    else if( strClass == "Private" )
        cTag |= JS_PRIVATE;

    if( mConstructedCheck->isChecked() )
    {
        cTag |= JS_CONSTRUCTED;
    }

    cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );
    cTag |= cPrimitive;

    JS_BIN_set( &binHeader, &cTag, 1 );
    JS_BIN_bitString( &binHeader, &pBitString );

    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binValue );
    JS_BER_getHeaderLength( binValue.nLen, &binLen );

    JS_BIN_appendBin( &binHeader, &binLen );

    JS_BIN_encodeHex( &binHeader, &pHex );
    mTagText->setText( pBitString );
    mHeaderText->setText( pHex );


end :
    JS_BIN_reset( &binLen );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binValue );
    if( pBitString ) JS_free( pBitString );
    if( pHex ) JS_free( pHex );
}

void InsertBerDlg::runInsert()
{
    QDialog::accept();
}

void InsertBerDlg::checkConstructed()
{
    bool bVal = mConstructedCheck->isChecked();

    makeHeader();
}

void InsertBerDlg::headerChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mHeaderLenText->setText( QString("%1").arg(nLen));
}

void InsertBerDlg::valueChanged()
{
    int nLen = mValueText->toPlainText().length() / 2;
    mValueLenText->setText( QString("%1").arg(nLen));

    makeHeader();
}

void InsertBerDlg::classChanged(int index)
{
    makeHeader();
}

void InsertBerDlg::primitiveChanged(int index )
{
    unsigned char cPrimitive = 0x00;
    cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );

    if( cPrimitive == JS_SET || cPrimitive == JS_SEQUENCE )
        mConstructedCheck->setChecked( true );

    makeHeader();
}
