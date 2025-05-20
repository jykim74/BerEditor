/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QStringList>
#include <QRegExpValidator>

#include "num_converter_dlg.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_util.h"
#include "ber_applet.h"
#include "common.h"

const QStringList sTypeList = { "Bit", "Decimal", "Hex" };

NumConverterDlg::NumConverterDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mBinChangeBtn, SIGNAL(clicked()), this, SLOT(binChange()));
    connect( mDecChangeBtn, SIGNAL(clicked()), this, SLOT(decChange()));
    connect( mHexChangeBtn, SIGNAL(clicked()), this, SLOT(hexChange()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    connect( mBitBtn, SIGNAL(clicked()), this, SLOT(clickInputBit()));
    connect( mDecimalBtn, SIGNAL(clicked()), this, SLOT(clickInputDec()));
    connect( mHexBtn, SIGNAL(clicked()), this, SLOT(clickInputHex()));

    connect( mInputText, SIGNAL(textChanged(QString)), this, SLOT(dataConversion()));

    mDecimalBtn->click();

    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

NumConverterDlg::~NumConverterDlg()
{

}

void NumConverterDlg::initialize()
{

}

void NumConverterDlg::dataConversion()
{
    BIN binSrc = {0,0};

    char *pBinOutput = NULL;
    char *pDecOutput = NULL;
    char *pHexOutput = NULL;

    const char *pTrimOut = NULL;

    int nNum = 0;

    QString strInput = mInputText->text();
    strInput.remove( QRegularExpression("[\t\r\n\\s]") );

    if( strInput.length() < 1 )
    {
//        berApplet->warningBox( tr( "Enter input data" ), this );
        clickOutputClear();
        mInputText->setFocus();
        return;
    }

    if( mBitBtn->isChecked() )
        nNum = 2;
    else if( mDecimalBtn->isChecked() )
        nNum = 10;
    else if( mHexBtn->isChecked() )
        nNum = 16;

    if( isValidNumFormat( strInput, nNum ) == false )
    {
        berApplet->warningBox( tr( "Input contains non-numeric values" ), this );
        return;
    }

    if( mBitBtn->isChecked() )
        JS_PKI_bitToBin( strInput.toStdString().c_str(), &binSrc );
    else if( mDecimalBtn->isChecked() )
        JS_PKI_decimalToBin( strInput.toStdString().c_str(), &binSrc );
    else if( mHexBtn->isChecked() )
    {
        QString strHex;

        if( strInput.length() % 2)
            strHex = "0";

        strHex += strInput;
        JS_BIN_decodeHex( strHex.toStdString().c_str(), &binSrc );
    }

    if( binSrc.nLen <= 0 ) goto end;

    JS_PKI_binToBit( &binSrc, &pBinOutput );

    if( binSrc.pVal[0] & 0xFF )
    {
        BIN binTmp = {0,0};
        JS_BIN_setChar( &binTmp, 0x00, 1 );
        JS_BIN_appendBin( &binTmp, &binSrc );
        JS_PKI_binToDecimal( &binTmp, &pDecOutput );
        JS_BIN_reset( &binTmp );
    }
    else
    {
        JS_PKI_binToDecimal( &binSrc, &pDecOutput );
    }

    JS_BIN_encodeHex( &binSrc, &pHexOutput );

    mDecOutputText->setPlainText( pDecOutput );
    mHexOutputText->setPlainText( pHexOutput );

    pTrimOut = JS_UTIL_trimChLeft( '0', pBinOutput );
    mBinOutputText->setPlainText( pTrimOut );

end :
    if( pBinOutput ) JS_free( pBinOutput );
    if( pDecOutput ) JS_free( pDecOutput );
    if( pHexOutput ) JS_free( pHexOutput );
    JS_BIN_reset( &binSrc );
    update();
}

void NumConverterDlg::binChange()
{
    QString strOutput = mBinOutputText->toPlainText();
    mBinOutputText->clear();

    mBitBtn->click();
    mInputText->setText( strOutput );
}

void NumConverterDlg::decChange()
{
    QString strOutput = mDecOutputText->toPlainText();
    mDecOutputText->clear();

    mDecimalBtn->click();
    mInputText->setText( strOutput );
}

void NumConverterDlg::hexChange()
{
    QString strOutput = mHexOutputText->toPlainText();
    mHexOutputText->clear();

    mHexBtn->click();
    mInputText->setText( strOutput );
}

void NumConverterDlg::clickInputClear()
{
    mInputText->clear();
}

void NumConverterDlg::clickOutputClear()
{
    mBinOutputText->clear();
    mDecOutputText->clear();
    mHexOutputText->clear();
}

void NumConverterDlg::clickInputHex()
{
    mInputText->clear();
    QRegExp regExp("^[0-9a-fA-F]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mInputText->setValidator( regVal );
    mInputText->setPlaceholderText( tr("valid characters: %1").arg( kHexChars ));
}

void NumConverterDlg::clickInputBit()
{
    mInputText->clear();
    QRegExp regExp("^[0-1]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mInputText->setValidator( regVal );
    mInputText->setPlaceholderText( tr("valid characters: %1").arg( kBinaryChars ));
}

void NumConverterDlg::clickInputDec()
{
    mInputText->clear();
    QRegExp regExp("^[0-9-]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mInputText->setValidator( regVal );
    mInputText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
}
