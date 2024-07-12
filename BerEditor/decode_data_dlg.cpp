/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "decode_data_dlg.h"
#include "ber_applet.h"
#include "common.h"

DecodeDataDlg::DecodeDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(viewData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
    connect( mTypeHex, SIGNAL(clicked()), this, SLOT(dataChanged()));
    connect( mTypeBase64, SIGNAL(clicked()), this, SLOT(dataChanged()));

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(findData()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clearData()));

    mTypeHex->setChecked(true);
    mViewBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

DecodeDataDlg::~DecodeDataDlg()
{

}

void DecodeDataDlg::viewData()
{
    int nType = 0;
    BIN binData = {0,0};

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;

    QString strData = mDataText->toPlainText();

    if( strData.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter your data"), this );
        mDataText->setFocus();
        return;
    }

    getBINFromString( &binData, nType, strData );
    berApplet->decodeData( &binData, "Unknown" );
    JS_BIN_reset( &binData );
    QDialog::accept();
}


QString DecodeDataDlg::getTextData()
{
    return mDataText->toPlainText();
}

void DecodeDataDlg::dataChanged()
{
    int nType = 0;

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void DecodeDataDlg::clearData()
{
    mDataText->clear();
}

void DecodeDataDlg::findData()
{
    BIN binData = {0,0};
    QString strPath = berApplet->curFolder();

    QString strFileName = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( strFileName.length() < 1 ) return;

    JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binData );
    mDataText->setPlainText( getHexString( &binData ));

    JS_BIN_reset( &binData );
    berApplet->setCurFile( strFileName );
}
