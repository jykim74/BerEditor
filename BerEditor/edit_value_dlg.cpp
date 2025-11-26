/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "edit_value_dlg.h"
#include "ber_item.h"
#include "js_bin.h"
#include "ber_model.h"
#include "ber_applet.h"
#include "common.h"
#include "make_value_dlg.h"
#include "ber_tree_view.h"
#include "mainwindow.h"


EditValueDlg::EditValueDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(runAdd()));
    connect( mModifyBtn, SIGNAL(clicked()), this, SLOT(runChange()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValueText()));
    connect( mBERText, SIGNAL(textChanged()), this, SLOT(changeBER()));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValueType(int)));
    connect( mMakeValueBtn, SIGNAL(clicked()), this, SLOT(clickMakeValue()));

    initialize();

    mModifyBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

EditValueDlg::~EditValueDlg()
{

}

void EditValueDlg::setHeadLabel( const QString strHead )
{
    mHeadLabel->setText( strHead );
}

void EditValueDlg::initialize()
{
    mValueTypeCombo->addItems( kDataTypeList );
    mValueTypeCombo->setCurrentText( kDataHex );
    mMakeValueBtn->hide();
}

void EditValueDlg::makeHeader()
{
    int ret = -1;
    unsigned char cTag = 0x00;
    unsigned char cPrimitive = 0x00;
    BIN binLen = {0,0};
    BIN binValue = {0,0};
    BIN binHeader = {0,0};
    char *pHex = NULL;
    char *pBitString = NULL;

    QString strClass = mClassText->text();
    QString strValue = mValueText->toPlainText();

    if( strClass == "Universal" )
        cTag |= JS_UNIVERSAL;
    else if( strClass == "Application" )
        cTag |= JS_APPLICATION;
    else if( strClass == "Content-Specific" )
        cTag |= JS_CONTEXT;
    else if( strClass == "Private" )
        cTag |= JS_PRIVATE;

    if( mConstructedLabel->text() == "Constructed"  )
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
        cPrimitive = JS_BER_getPrimitiveTag( mTagText->text().toStdString().c_str() );
        cTag |= cPrimitive;
    }

    JS_BIN_set( &binHeader, &cTag, 1 );
    JS_BIN_bitString( &binHeader, &pBitString );

    ret = getBINFromString( &binValue, mValueTypeCombo->currentText(), strValue );
    if( ret < 0 ) goto end;

    JS_BER_getHeaderLength( binValue.nLen, &binLen );

    JS_BIN_appendBin( &binHeader, &binLen );

    JS_BIN_encodeHex( &binHeader, &pHex );
    mLenText->setText( getHexString( &binLen ));
    mHeaderText->setText( pHex );
    mBERText->setPlainText( getData() );

end :
    JS_BIN_reset( &binLen );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binValue );
    if( pBitString ) JS_free( pBitString );
    if( pHex ) JS_free( pHex );
}

void EditValueDlg::setItem(BerItem *pItem)
{
    BIN binHeader = {0,0};
    BIN binValue = {0,0};
    BIN binTag = {0,0};
    QString strValue;
    char *pHeader = NULL;
    char *pBitString = NULL;
    bool bConstructed = false;

    ber_item_ = pItem;
    BerModel *ber_model = (BerModel *)ber_item_->model();
    const BIN& binBer = ber_model->getBER();

    ber_item_ = pItem;
    mClassText->setText( ber_item_->GetClassString() );

    if( mClassText->text() == "Context-specific" )
    {
        mTagText->setEnabled(false);
        mTagLabel->setText(tr("Number"));
    }
    else
    {
        mTagText->setEnabled(true);
        mTagText->setText( ber_item_->GetTagString() );
    }

    mNumText->setText( QString("%1").arg( ber_item_->GetTag(), 2, 16, QLatin1Char('0'))  );

    bConstructed = ber_item_->isConstructed();
    if( bConstructed )
    {
        mConstructedLabel->setText( "Constructed" );
        mValueText->setReadOnly( true );
        mValueText->setStyleSheet( kReadOnlyStyle );
        mModifyBtn->hide();
        mCloseBtn->setDefault(true);
    }
    else
    {
        mConstructedLabel->setText( "Primitive" );

        if( ber_item_->tag_ == JS_NULLTAG )
        {
            mValueText->setReadOnly( true );
            mValueText->setStyleSheet( kReadOnlyStyle );
            mModifyBtn->hide();
        }
        else
        {
            mValueText->setReadOnly( false );
            mModifyBtn->show();
        }

        if( ber_item_->tag_ == JS_INTEGER || ber_item_->tag_ == JS_BITSTRING || ber_item_->tag_ == JS_OID )
            mMakeValueBtn->show();
    }

    QString strOffset;
    strOffset = QString( "%1" ).arg( ber_item_->GetOffset() );
    mOffsetText->setText(strOffset);

    QString strLevel;
    strLevel = QString( "%1" ).arg( ber_item_->GetLevel() );
    mLevelText->setText(strLevel);

    JS_BIN_set( &binHeader, ber_item_->header_, ber_item_->header_size_);
    JS_BIN_encodeHex( &binHeader, &pHeader );
    mHeaderText->setText( pHeader );

    JS_BIN_set( &binTag, binHeader.pVal, 1 );
    JS_BIN_bitString( &binTag, &pBitString );
    mTagBitText->setText( pBitString );

    JS_BIN_set( &binValue, &binBer.pVal[ber_item_->GetOffset() + ber_item_->GetHeaderSize()], ber_item_->GetLength() );
    strValue = getStringFromBIN( &binValue, mValueTypeCombo->currentText(), &binValue );
    mValueText->setPlainText( strValue );

    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binTag );
    if( pHeader ) JS_free( pHeader );
    if( pBitString ) JS_free( pBitString );
}

QString EditValueDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    int ret = getBINFromString( &binData, mValueTypeCombo->currentText(), strValue );
    if( ret < 0 ) goto end;

    strData = mHeaderText->text();
    strData += getHexString( &binData );

end :
    JS_BIN_reset( &binData );

    return strData;
}

void EditValueDlg::runChange()
{
    int ret = 0;

    BIN binNewVal = {0,0};
    QString strValue = mValueText->toPlainText();
    BerModel *ber_model = (BerModel *)ber_item_->model();

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to modify it?" ), this, false );
    if( bVal == false ) return;

    ret = getBINFromString( &binNewVal, mValueTypeCombo->currentText(), strValue );
    FORMAT_WARN_GO(ret);

    ret = ber_model->modifyItem( ber_item_, &binNewVal );

    if( ret == JSR_OK )
    {
        int nOffset = ber_item_->GetOffset();

        berApplet->mainWindow()->reloadData();
        const BerItem *findItem = ber_model->findItemByOffset( nullptr, nOffset );
        if( findItem )
        {
            QModelIndex idx = findItem->index();

            berApplet->mainWindow()->berTree()->expandToTop( findItem );
            berApplet->mainWindow()->berTree()->clicked( idx );
            berApplet->mainWindow()->berTree()->setCurrentIndex( idx );
        }
    }
    else
    {
        berApplet->warningBox( tr( "failed to modify: %1").arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binNewVal );

    if( ret == 0 )
        QDialog::accept();
    else
        reject();
}


void EditValueDlg::runAdd()
{
    int ret = 0;
    BIN binData = {0,0};

    BerModel *ber_model = (BerModel *)ber_item_->model();
    BerItem *parentItem = (BerItem *)ber_item_->parent();

    QString strData = getData();
    const BerItem *child = nullptr;

    if( parentItem == NULL )
    {
        berApplet->warningBox( tr( "Top-level item cannot be added."), this );
        QDialog::reject();
        return;
    }

    if( parentItem->isConstructed() == false )
    {
        berApplet->warningBox( tr( "Parent item is not constructed."), this );
        QDialog::reject();
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), this, false );
    if( bVal == false ) return;

    bool bFirst = mFirstSetCheck->isChecked();

    JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
    child = ber_model->addItem( parentItem, bFirst, &binData );
    if( child )
    {
        int nOffset = child->offset_;
        berApplet->mainWindow()->reloadData();

        const BerItem *findItem = ber_model->findItemByOffset( nullptr, nOffset );
        if( findItem )
        {
            QModelIndex idx = findItem->index();
            berApplet->mainWindow()->berTree()->expandToTop( findItem );
            berApplet->mainWindow()->berTree()->clicked( idx );
            berApplet->mainWindow()->berTree()->setCurrentIndex( idx );
        }
    }
    else
    {
        berApplet->warningBox( tr( "failed to insert" ), this );
    }

 end :
    JS_BIN_reset( &binData );

    if( ret == 0 )
        QDialog::accept();
    else
        QDialog::reject();
}

void EditValueDlg::changeValueText()
{
    QString strValue = mValueText->toPlainText();
    QString strLen = getDataLenString( mValueTypeCombo->currentText(), strValue );
    mValueLenText->setText( QString("%1").arg(strLen));

    makeHeader();
}

void EditValueDlg::changeBER()
{
    QString strBER = mBERText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strBER );
    mBERLenText->setText( QString("%1").arg( strLen ));
}

void EditValueDlg::changeValueType(int index)
{
    changeValueText();
}

void EditValueDlg::clickMakeValue()
{
    BIN binVal = {0,0};
    MakeValueDlg makeValue;
    QString strValue = mValueText->toPlainText();
    QString strType;

    if( ber_item_->tag_ == JS_BITSTRING )
        strType = "Bit";
    else if( ber_item_->tag_ == JS_INTEGER )
        strType = "Integer";
    else if( ber_item_->tag_ == JS_OID )
        strType = "OID";
    else
        return;

    getBINFromString( &binVal, mValueTypeCombo->currentText(), strValue );
    makeValue.setValue( strType, &binVal );

    if( makeValue.exec() == QDialog::Accepted )
    {
        mValueTypeCombo->setCurrentText( kDataHex );
        mValueText->setPlainText( makeValue.getValue() );
    }

    JS_BIN_reset( &binVal );
}
