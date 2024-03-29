/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(valueChanged()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(numChanged()));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mPrimitiveCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(primitiveChanged(int)));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValueType(int)));

    initialize();
    mCloseBtn->setFocus();
}

InsertBerDlg::~InsertBerDlg()
{

}

QString InsertBerDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    getBINFromString( &binData, mValueTypeCombo->currentText(), strValue );

    strData = mHeaderText->text();
    strData += getHexString( &binData );

    JS_BIN_reset( &binData );

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
    mValueTypeCombo->addItems( kValueTypeList );
    mValueTypeCombo->setCurrentIndex(1);
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
    QString strValue = mValueText->toPlainText();

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

    if( cTag & JS_CONTEXT )
    {
        unsigned char cNum = mNumText->text().toInt( nullptr, 16 );
        if( cNum > 0x1F )
        {
            berApplet->warningBox( tr( "Invalid Number: %1").arg(cNum), this );
            return;
        }

        cTag |= cNum;
    }
    else
    {
        cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );
        cTag |= cPrimitive;
    }

    JS_BIN_set( &binHeader, &cTag, 1 );
    JS_BIN_bitString( &binHeader, &pBitString );

    getBINFromString( &binValue, mValueTypeCombo->currentText(), strValue );
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

void InsertBerDlg::valueChanged()
{
    QString strValue = mValueText->toPlainText();

    int nLen = getDataLen( mValueTypeCombo->currentText(), strValue );
    mValueLenText->setText( QString("%1").arg(nLen));

    makeHeader();
}

void InsertBerDlg::numChanged()
{
    makeHeader();
}

void InsertBerDlg::classChanged(int index)
{
    if( index == 2 )
    {
        mPrimitiveCombo->hide();
        mNumText->setReadOnly( false );
        mNumText->clear();
        mTagLabel->setText(tr("Number"));
    }
    else
    {
        mPrimitiveCombo->show();
        mNumText->setReadOnly( true );
        mTagLabel->setText(tr("Tag"));
    }

    makeHeader();
}

void InsertBerDlg::primitiveChanged(int index )
{
    unsigned char cPrimitive = 0x00;
    cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );

    if( cPrimitive == JS_SET || cPrimitive == JS_SEQUENCE )
        mConstructedCheck->setChecked( true );

    mNumText->setText( QString( "%1" ).arg( cPrimitive, 2, 16, QLatin1Char('0')));
}

void InsertBerDlg::changeValueType( int index )
{
    valueChanged();
}
