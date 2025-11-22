/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */

#include <QTimer>
#include <QThread>

#include "make_ber_dlg.h"
#include "mainwindow.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"
#include "make_value_dlg.h"

const QStringList kClassList = { "Universal", "Application", "Content-Specific", "Private" };

MakeBerDlg::MakeBerDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(runMake()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mConstructedCheck, SIGNAL(clicked()), this, SLOT(checkConstructed()));
    connect( mIndefiniteCheck, SIGNAL(clicked()), this, SLOT(checkIndefinite()));
    connect( mValueClearBtn, SIGNAL(clicked()), this, SLOT(clearValue()));

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(valueChanged()));
    connect( mBERText, SIGNAL(textChanged()), this, SLOT(berChanged()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(numChanged()));
    connect( mClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(classChanged(int)));
    connect( mPrimitiveCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(primitiveChanged(int)));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValueType(int)));
    connect( mMakeValueBtn, SIGNAL(clicked()), this, SLOT(clickMakeValue()));

    initialize();
    mMakeBtn->setDefault(true);
    mValueText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mValueClearBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeBerDlg::~MakeBerDlg()
{

}

void MakeBerDlg::setHeadLabel( const QString strHead )
{
    mHeadLabel->setText( strHead );
}

QString MakeBerDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    if( strValue.length() > 0 )
    {
        int ret = getBINFromString( &binData, mValueTypeCombo->currentText(), strValue );
        if( ret <= 0 ) goto end;
    }

    strData = mHeaderText->text();
    strData += getHexString( &binData );

    if( mConstructedCheck->isChecked() == true && mIndefiniteCheck->isChecked() == true )
        strData += "0000";

end:
    JS_BIN_reset( &binData );

    return strData;
}

void MakeBerDlg::initUI()
{
    mValueText->setAcceptDrops(false);
    mClassCombo->addItems( kClassList );
    mIndefiniteCheck->setEnabled( false );

    int nPrimitiveCnt = JS_BER_getPrimitiveCount();

    mPrimitiveCombo->addItem( "None" );

    for( int i = 0; i < nPrimitiveCnt; i++ )
    {
        const char *pName = JS_BER_getPrimitiveNameAt( i );
        if( strcasecmp( pName, JS_NAME_EOC ) == 0 )
            continue;

        mPrimitiveCombo->addItem( pName );
    }

    mValueTypeCombo->addItems( kDataTypeList );
}

void MakeBerDlg::initialize()
{
    classChanged(0);
}

void MakeBerDlg::clearValue()
{
    mValueText->clear();
}

void MakeBerDlg::makeHeader()
{
    int ret = -1;
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
    else if( cTag & JS_UNIVERSAL )
    {
        cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );
        cTag |= cPrimitive;
    }
    else
    {
        unsigned char cNum = mNumText->text().toInt( nullptr, 16 );
        cTag |= cNum;
    }

    JS_BIN_set( &binHeader, &cTag, 1 );
    JS_BIN_bitString( &binHeader, &pBitString );

    ret = getBINFromString( &binValue, mValueTypeCombo->currentText(), strValue );
    if( ret < 0 ) goto end;

    if( mConstructedCheck->isChecked() == true && mIndefiniteCheck->isChecked() == true )
    {
        JS_BIN_appendCh( &binHeader, 0x80, 1 );
    }
    else
    {
        JS_BER_getHeaderLength( binValue.nLen, &binLen );
        JS_BIN_appendBin( &binHeader, &binLen );
    }

    JS_BIN_encodeHex( &binHeader, &pHex );
    mLenText->setText( getHexString(&binLen));
    mTagText->setText( pBitString );
    mHeaderText->setText( pHex );
    mBERText->setPlainText( getData() );

end :
    JS_BIN_reset( &binLen );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binValue );
    if( pBitString ) JS_free( pBitString );
    if( pHex ) JS_free( pHex );
}

void MakeBerDlg::runMake()
{
    if( mTagText->text().toInt() <= 0 )
    {
        berApplet->warningBox( tr( "Select Tag" ), this );
        return;
    }

    QDialog::accept();
}

void MakeBerDlg::checkConstructed()
{
    bool bVal = mConstructedCheck->isChecked();


    if( mPrimitiveCombo->isEnabled() == true )
    {
        unsigned char cPrimitive = 0x00;
        cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );

        if( cPrimitive == JS_SET || cPrimitive == JS_SEQUENCE )
        {
            if( bVal == false )
            {
                mConstructedCheck->setChecked( true );
                berApplet->warningBox( tr("SET and SEQUENCE cannot be changed"), this );
                return;
            }
        }
        else
        {
            if( bVal == true )
            {
                mConstructedCheck->setChecked( false );
                berApplet->warningBox( tr("Only SET and SEQUENCE are supported"), this );
                return;
            }
        }
    }

    mIndefiniteCheck->setEnabled( bVal );
    makeHeader();
}

void MakeBerDlg::checkIndefinite()
{
    makeHeader();
}

void MakeBerDlg::valueChanged()
{
    QString strValue = mValueText->toPlainText();

    QString strLen = getDataLenString( mValueTypeCombo->currentText(), strValue );
    mValueLenText->setText( QString("%1").arg(strLen));

    makeHeader();
}

void MakeBerDlg::berChanged()
{
    QString strBER = mBERText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strBER );
    mBERLenText->setText( QString("%1").arg( strLen ));
}

void MakeBerDlg::numChanged()
{
    makeHeader();
}

void MakeBerDlg::classChanged(int index)
{
    mNumText->clear();

    if( index == 0 )
    {
        mPrimitiveCombo->setEnabled(true);
        mNumText->setStyleSheet( kReadOnlyStyle );
        mNumText->setReadOnly( true );
        mTagLabel->setText(tr("Tag"));
        primitiveChanged( index );
        mMakeValueBtn->show();
    }
    else
    {
        mPrimitiveCombo->setEnabled( false );
        mNumText->setStyleSheet( "" );
        mNumText->setReadOnly( false );
        mTagLabel->setText(tr("Number"));
        mMakeValueBtn->hide();
    }

    makeHeader();
}

void MakeBerDlg::primitiveChanged(int index )
{
    unsigned char cPrimitive = 0x00;
    cPrimitive = JS_BER_getPrimitiveTag( mPrimitiveCombo->currentText().toStdString().c_str() );

    if( cPrimitive == JS_NULLTAG )
    {
        mValueText->clear();
        mValueText->setReadOnly( true );
        mValueText->setStyleSheet( kReadOnlyStyle );
    }
    else
    {
        mValueText->setReadOnly( false );
        mValueText->setStyleSheet( "" );
    }

    if( cPrimitive == JS_SET || cPrimitive == JS_SEQUENCE )
        mConstructedCheck->setChecked( true );
    else
        mConstructedCheck->setChecked( false );

    checkConstructed();

    if( cPrimitive == JS_BITSTRING || cPrimitive == JS_INTEGER || cPrimitive == JS_OID )
        mMakeValueBtn->setEnabled( true );
    else
        mMakeValueBtn->setEnabled( false );

    mNumText->setText( QString( "%1" ).arg( cPrimitive, 2, 16, QLatin1Char('0')));
}

void MakeBerDlg::changeValueType( int index )
{
    QString strType = mValueTypeCombo->currentText();
    if( strType == kDataHex )
        mMakeValueBtn->setEnabled( true );
    else
        mMakeValueBtn->setEnabled( false );

    valueChanged();
}

void MakeBerDlg::clickMakeValue()
{
    QString strPrimitive = mPrimitiveCombo->currentText();
    MakeValueDlg makeValue;
    QString strType;
    BIN binVal = {0,0};
    QString strValue = mValueText->toPlainText();

    if( strPrimitive == "BitString" )
        strType = "Bit";
    else if( strPrimitive == "Integer" )
        strType = "Integer";
    else if( strPrimitive == "ObjectIdentifier" )
        strType = "OID";
    else
        return;

    getBINFromString( &binVal, mValueTypeCombo->currentText(), strValue );
    makeValue.setValue( strType, &binVal );

    if( makeValue.exec() == QDialog::Accepted )
    {
        mValueTypeCombo->setCurrentText( "Hex" );
        mValueText->setPlainText( makeValue.getValue() );
    }
}
