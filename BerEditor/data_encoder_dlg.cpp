/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "data_encoder_dlg.h"
#include "js_bin.h"
#include "js_util.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"

static QStringList enTypes = {
    "String",
    "Hex",
    "Base64",
    "URL"
};

DataEncoderDlg::DataEncoderDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mOutputTypeCombo->addItems( enTypes );

    connect( mFindFileBtn, SIGNAL(clicked()), this, SLOT(clickFindFile()));
    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(onClickEncodeBtn()));
    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outTypeChanged(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mInputTypeURL, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeHexBtn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeBase64Btn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeStringBtn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    mCloseBtn->setFocus();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

DataEncoderDlg::~DataEncoderDlg()
{

}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

void DataEncoderDlg::clickFindFile()
{
    QString strPath = berApplet->curFolder();

    QString strFile = findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strFile.length() > 0 )
    {
        mInputTypeHexBtn->setChecked(true);
        BIN binFile = {0,0};
        JS_BIN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binFile );

        mInputText->setPlainText( getHexString( &binFile ));
        JS_BIN_reset( &binFile );
    }
}

void DataEncoderDlg::onClickEncodeBtn()
{
    int input_type = 0;
    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();
    QString outputStr = "";

    if( inputStr.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        return;
    }

    if( mInputTypeStringBtn->isChecked() )
        input_type = DATA_STRING;
    else if( mInputTypeHexBtn->isChecked() )
        input_type = DATA_HEX;
    else if( mInputTypeBase64Btn->isChecked() )
        input_type = DATA_BASE64;
    else if( mInputTypeURL->isChecked() )
        input_type = DATA_URL;

    getBINFromString( &binSrc, input_type, inputStr );
    outputStr = getStringFromBIN( &binSrc, mOutputTypeCombo->currentText(), mShowPrintTextCheck->isChecked() );
    mOutputText->setPlainText( outputStr );

    JS_BIN_reset(&binSrc);
    repaint();
}

void DataEncoderDlg::outTypeChanged(int index)
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

void DataEncoderDlg::inputChanged()
{
    int nInputType = 0;

    if( mInputTypeStringBtn->isChecked() )
        nInputType = DATA_STRING;
    else if( mInputTypeHexBtn->isChecked() )
        nInputType = DATA_HEX;
    else if( mInputTypeBase64Btn->isChecked() )
        nInputType = DATA_BASE64;
    else if( mInputTypeURL->isChecked() )
        nInputType = DATA_URL;

    QString strLen = getDataLenString( nInputType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void DataEncoderDlg::outputChanged()
{
    QString strLen = getDataLenString( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void DataEncoderDlg::clickChange()
{
    if( mOutputTypeCombo->currentText() == "String" )
        mInputTypeStringBtn->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "Hex" )
        mInputTypeHexBtn->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "Base64" )
        mInputTypeBase64Btn->setChecked(true);
    else if( mOutputTypeCombo->currentText() == "URL" )
        mInputTypeURL->setChecked(true);

    QString strOut = mOutputText->toPlainText();
    mInputText->setPlainText( strOut );
    mOutputText->clear();
}

void DataEncoderDlg::clickInputClear()
{
    mInputText->clear();
}

void DataEncoderDlg::clickOutputClear()
{
    mOutputText->clear();
}
