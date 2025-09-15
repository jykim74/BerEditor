#include "make_value_dlg.h"
#include "common.h"
#include "js_pki.h"
#include "js_pki_tools.h"

const QStringList kTypeList = { "Integer", "Bit", "OID" };

MakeValueDlg::MakeValueDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputText, SIGNAL(textChanged(const QString&)), this, SLOT(makeValue()));
    connect( mHexText, SIGNAL(textChanged()), this, SLOT(hexChanged()));
    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(typeChanged()));

    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeValueDlg::~MakeValueDlg()
{

}

void MakeValueDlg::initialize()
{
    mTypeCombo->addItems( kTypeList );
}

void MakeValueDlg::clickOK()
{
    value_ = mHexText->toPlainText();
    QDialog::accept();
}

void MakeValueDlg::makeValue()
{
    QString strType = mTypeCombo->currentText();
    QString strInput = mInputText->text();
    BIN binOut = {0,0};

    if( strType == "Integer" )
    {
        JS_PKI_decimalToBin( strInput.toStdString().c_str(), &binOut );
    }
    else if( strType == "Bit" )
    {
        int nLeft = 0;
        int nMod = strInput.length() % 8;
        if( nMod > 0 ) nLeft = 8 - nMod;

        BIN binVal = {0,0};

        if( nLeft > 0 ) strInput += QString( "%1" ).arg( '0', nLeft, QLatin1Char('0'));
        unsigned char cCh = nLeft;
        JS_BIN_setChar( &binOut, cCh, 1 );

        JS_PKI_bitToBin( strInput.toStdString().c_str(), &binVal );
        JS_BIN_appendBin( &binOut, &binVal );
        JS_BIN_reset( &binVal );
    }
    else if( strType == "OID" )
    {
        JS_PKI_getOIDValueFromString( strInput.toStdString().c_str(), &binOut );
    }

    mHexText->setPlainText( getHexString(&binOut));
    JS_BIN_reset( &binOut );
}

void MakeValueDlg::hexChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mHexText->toPlainText() );
    mHexLenText->setText( QString("%1").arg(strLen));
}

void MakeValueDlg::typeChanged()
{
    QString strType = mTypeCombo->currentText();
    mInputText->clear();

    if( strType == "Integer" )
    {
        QRegExp regExp("^[0-9-]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
        mInputText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
    }
    else if( strType == "Bit" )
    {
        QRegExp regExp("^[0-1]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
        mInputText->setPlaceholderText( tr("valid characters: %1").arg( kBinaryChars ));
    }
    else if( strType == "OID" )
    {
        QRegExp regExp("^[0-9.]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
        mInputText->setPlaceholderText( tr("Object Identifier") );
    }
}
