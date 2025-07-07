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

    initUI();

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
    resize( minimumSizeHint().width(), minimumSizeHint().height());
}

DecodeDataDlg::~DecodeDataDlg()
{

}

void DecodeDataDlg::initUI()
{
    mDataText->setPlaceholderText( tr( "Hex value" ));
}

void DecodeDataDlg::viewData()
{
    int nType = 0;
    BIN binData = {0,0};

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;
    else if( mTypeBase64URL->isChecked() )
        nType = DATA_BASE64URL;

    QString strData = mDataText->toPlainText();

    if( strData.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter data"), this );
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
    int nType = DATA_STRING;

    if( mTypeHex->isChecked() )
    {
        nType = DATA_HEX;
        mDataText->setPlaceholderText( tr( "Hex value" ));
    }
    else if( mTypeBase64->isChecked() )
    {
        nType = DATA_BASE64;
        mDataText->setPlaceholderText( tr( "Base64 or PEM value" ));
    }
    else if( mTypeBase64URL->isChecked() )
    {
        nType = DATA_BASE64URL;
        mDataText->setPlaceholderText( tr( "Base64UL value" ));
    }

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
    QString strPath;

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( strFileName.length() < 1 ) return;

    JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binData );

    if( mTypeHex->isChecked() )
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
}
