/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "data_converter_dlg.h"
#include "js_bin.h"
#include "js_util.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"

static QStringList enTypes = {
    "String",
    "Hex",
    "Base64",
    "URL",
    "Base64URL"
};

DataConverterDlg::DataConverterDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mOutputTypeCombo->addItems( enTypes );

    connect( mFindFileBtn, SIGNAL(clicked()), this, SLOT(clickFindFile()));
    connect( mWriteBinBtn, SIGNAL(clicked()), this, SLOT(clickWriteBin()));
    connect( mConvertBtn, SIGNAL(clicked()), this, SLOT(onClickConvertBtn()));
    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outTypeChanged(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mInputTypeURLCheck, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeHexCheck, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeBase64Check, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeStringCheck, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeBase64URLCheck, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    initialize();

    mConvertBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    resize(minimumSizeHint().width() + 40, minimumSizeHint().height());
#else
    resize(minimumSizeHint().width(), minimumSizeHint().height());
#endif

}

DataConverterDlg::~DataConverterDlg()
{

}

void DataConverterDlg::initialize()
{
    mOutputTab->setCurrentIndex(0);
    mOutputTypeCombo->setCurrentIndex(1);
}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

void DataConverterDlg::clickFindFile()
{
    QString strPath;

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strFile.length() > 0 )
    {
        mInputTypeHexCheck->setChecked(true);
        BIN binFile = {0,0};
        JS_BIN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binFile );

        mInputText->setPlainText( getHexString( &binFile ));
        JS_BIN_reset( &binFile );
    }
}

void DataConverterDlg::clickWriteBin()
{
    int ret = 0;
    BIN binOut = {0,0};

    QString strOut = mOutputText->toPlainText();
    QString strType = mOutputTypeCombo->currentText();
    QString strFile;
    QString strPath = berApplet->curPath();

    int nOutLen = strOut.length();

    if( nOutLen < 1 )
    {
        berApplet->warningBox( tr( "There is no output" ), this );
        mOutputText->setFocus();
        return;
    }

    getBINFromString( &binOut, strType, strOut );
    strFile = berApplet->findSaveFile( this, JS_FILE_TYPE_BIN, strPath );
    if( strFile.length() > 0 )
    {
        ret = JS_BIN_fileWrite( &binOut, strFile.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Binary save success" ), this );
        }
        else
        {
            berApplet->warningBox( tr("Binary save failed"), this );
        }
    }

    JS_BIN_reset( &binOut );
}

void DataConverterDlg::onClickConvertBtn()
{
    int input_type = 0;
    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();
    QString outputStr = "";

    int nInputLen = inputStr.length();

    if( nInputLen < 1 )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mInputText->setFocus();
        return;
    }

    if( mInputTypeStringCheck->isChecked() )
        input_type = DATA_STRING;
    else if( mInputTypeHexCheck->isChecked() )
        input_type = DATA_HEX;
    else if( mInputTypeBase64Check->isChecked() )
        input_type = DATA_BASE64;
    else if( mInputTypeBase64URLCheck->isChecked())
        input_type = DATA_BASE64URL;
    else if( mInputTypeURLCheck->isChecked() )
        input_type = DATA_URL;

    getBINFromString( &binSrc, input_type, inputStr );
    outputStr = getStringFromBIN( &binSrc, mOutputTypeCombo->currentText(), mShowPrintTextCheck->isChecked() );
    mOutputText->setPlainText( outputStr );
    makeDump( &binSrc );

    JS_BIN_reset(&binSrc);
    update();
}

void DataConverterDlg::outTypeChanged(int index)
{
    if( index == 0 )
    {
        mShowPrintTextCheck->setEnabled(true);
    }
    else
    {
        mShowPrintTextCheck->setEnabled(false);
    }
}

void DataConverterDlg::inputChanged()
{
    int nInputType = 0;
    QString strInput = mInputText->toPlainText();

    if( mInputTypeStringCheck->isChecked() )
        nInputType = DATA_STRING;
    else if( mInputTypeHexCheck->isChecked() )
        nInputType = DATA_HEX;
    else if( mInputTypeBase64Check->isChecked() )
        nInputType = DATA_BASE64;
    else if( mInputTypeBase64URLCheck->isChecked() )
        nInputType = DATA_BASE64URL;
    else if( mInputTypeURLCheck->isChecked() )
        nInputType = DATA_URL;

    QString strLen = getDataLenString( nInputType, strInput );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void DataConverterDlg::outputChanged()
{
    QString strLen = getDataLenString( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void DataConverterDlg::clickChange()
{
    if( mOutputTypeCombo->currentText() == "String" )
        mInputTypeStringCheck->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "Hex" )
        mInputTypeHexCheck->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "Base64" )
        mInputTypeBase64Check->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "Base64URL" )
        mInputTypeBase64URLCheck->setChecked( true );
    else if( mOutputTypeCombo->currentText() == "URL" )
        mInputTypeURLCheck->setChecked(true);

    QString strOut = mOutputText->toPlainText();
    mInputText->setPlainText( strOut );
    mOutputText->clear();
    mDumpText->clear();
}

void DataConverterDlg::clickInputClear()
{
    mInputText->clear();
}

void DataConverterDlg::clickOutputClear()
{
    mOutputText->clear();
    mDumpText->clear();
}

void DataConverterDlg::makeDump( const BIN *pData )
{
    mDumpText->clear();
    if( pData == NULL || pData->nLen <= 0 ) return;

    int nLeft = pData->nLen;
    int nWidth = 16;
    int nBlock = 0;
    int nPos = 0;

    BIN binPart = {0,0};

    while( nLeft > 0 )
    {
        if( nLeft > nWidth )
            nBlock = nWidth;
        else
            nBlock = nLeft;

        char *pDump = NULL;
        binPart.pVal = pData->pVal + nPos;
        binPart.nLen = nBlock;

        JS_BIN_dumpString( &binPart, &pDump );

        mDumpText->appendPlainText( QString( "%1: %2 | %3")
                                       .arg( nPos, 6, 16, QLatin1Char('0') )
                                       .arg( getHexString2( &binPart ), -48, QLatin1Char(' '))
                                       .arg( pDump) );

        nPos += nBlock;
        nLeft -= nBlock;
        if( pDump ) JS_free( pDump );
    }
}
