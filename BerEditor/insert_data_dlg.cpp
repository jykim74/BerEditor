/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "insert_data_dlg.h"
#include "ber_applet.h"
#include "common.h"

InsertDataDlg::InsertDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(viewData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
    connect( mTypeHex, SIGNAL(clicked()), this, SLOT(dataChanged()));
    connect( mTypeBase64, SIGNAL(clicked()), this, SLOT(dataChanged()));

    mTypeHex->setChecked(true);
    mViewBtn->setDefault(true);
}

InsertDataDlg::~InsertDataDlg()
{

}

void InsertDataDlg::viewData()
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


QString InsertDataDlg::getTextData()
{
    return mDataText->toPlainText();
}

void InsertDataDlg::dataChanged()
{
    int nType = 0;

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(nLen));
}
