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
        JS_PKI_bitToBin( strInput.toStdString().c_str(), &binOut );
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
    int nLen = getDataLen( DATA_HEX, mHexText->toPlainText() );
    mHexLenText->setText( QString("%1").arg(nLen));
}

void MakeValueDlg::typeChanged()
{
    QRegExp regExp("^[0-1]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );

    QString strType = mTypeCombo->currentText();

    if( strType == "Integer" )
    {
        QRegExp regExp("^[0-9-]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
    }
    else if( strType == "Bit" )
    {
        QRegExp regExp("^[0-1]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
    }
    else if( strType == "OID" )
    {
        QRegExp regExp("^[0-9.]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mInputText->setValidator( regVal );
    }
}
