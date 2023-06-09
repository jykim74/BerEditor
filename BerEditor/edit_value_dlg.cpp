#include "edit_value_dlg.h"
#include "ber_item.h"
#include "js_bin.h"
#include "ber_model.h"
#include "ber_applet.h"
#include "common.h"


EditValueDlg::EditValueDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(runAdd()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(runDelete()));
    connect( mModifyBtn, SIGNAL(clicked()), this, SLOT(runChange()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValueText()));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValueType(int)));

    initialize();

    mCloseBtn->setFocus();
}

EditValueDlg::~EditValueDlg()
{

}

void EditValueDlg::initialize()
{
    mValueTypeCombo->addItems( kValueTypeList );
    mValueTypeCombo->setCurrentIndex(1);
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
    BIN& binBer = ber_model->getBer();

    ber_item_ = pItem;
    mClassText->setText( ber_item_->GetClassString() );
    mTagText->setText( ber_item_->GetTagString() );

    bConstructed = ber_item_->isConstructed();
    if( bConstructed )
        mConstructedLabel->setText( "Constructed" );
    else
        mConstructedLabel->setText( "" );

    QString strOffset;
    strOffset.sprintf( "%d", ber_item_->GetOffset() );
    mOffsetText->setText(strOffset);

    QString strLength;
    strLength.sprintf( "%d", ber_item_->GetLength() );
    mLengthText->setText( strLength );

    QString strLevel;
    strLevel.sprintf( "%d", ber_item_->GetLevel() );
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

void EditValueDlg::runChange()
{
    int ret = 0;
    int nDiffLen = 0;
    int nOrgLen = 0;
    int nOrgHeaderLen = 0;

    BIN binNewVal = {0,0};
    BIN binHeader = {0,0};
    BIN binNewItem = {0,0};
    QModelIndexList indexList;
    QString strValue = mValueText->toPlainText();

    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();

    getBINFromString( &binNewVal, mValueTypeCombo->currentText(), strValue );

    nOrgLen = ber_item_->GetLength();
    nOrgHeaderLen = ber_item_->GetHeaderSize();

    ber_item_->changeLength( binNewVal.nLen, &nDiffLen );
    ber_item_->getHeaderBin( &binHeader );
    JS_BIN_copy( &binNewItem, &binHeader );
    JS_BIN_appendBin( &binNewItem, &binNewVal );

    ret = JS_BIN_changeBin( ber_item_->GetOffset(), nOrgHeaderLen + nOrgLen, &binNewItem, &binBer );
    ber_model->resizeParentHeader( nDiffLen, ber_item_, indexList );

    JS_BIN_reset( &binNewVal );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binNewItem );

    if( ret == 0 ) QDialog::accept();
}


void EditValueDlg::runDelete()
{
    int ret = 0;
    int nDiffLen = 0;
    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();
    QModelIndexList indexList;

    BerItem *parentItem = (BerItem *)ber_item_->parent();
    if( parentItem == NULL )
    {
        berApplet->warningBox( tr("Root Item can not be deleted"), this );
        QDialog::reject();
        return;
    }

    nDiffLen = ber_item_->GetHeaderSize();
    nDiffLen += ber_item_->GetLength();

    ret = JS_BIN_removeBin( ber_item_->GetOffset(), nDiffLen, &binBer );
    ber_model->resizeParentHeader( -nDiffLen, ber_item_, indexList );

    if( ret == 0 ) QDialog::accept();
}

void EditValueDlg::runAdd()
{
    int ret = 0;
    int nDiffLen = 0;
    BIN binVal = {0,0};
    BIN binItem = {0,0};
    BerModel *ber_model = (BerModel *)ber_item_->model();
    BerItem *parentItem = (BerItem *)ber_item_->parent();
    BIN& binBer = ber_model->getBer();
    QModelIndexList indexList;
    QString strValue = mValueText->toPlainText();

    if( parentItem == NULL )
    {
        berApplet->warningBox( QString( "Root Item can not be added."), this );
        QDialog::reject();
        return;
    }

    getBINFromString( &binVal, mValueTypeCombo->currentText(), strValue );

    ber_item_->changeLength( binVal.nLen, &nDiffLen );
    nDiffLen = ber_item_->GetHeaderSize();
    nDiffLen += ber_item_->GetLength();

    JS_BIN_set( &binItem, ber_item_->GetHeader(), ber_item_->GetHeaderSize() );
    JS_BIN_appendBin( &binItem, &binVal );

    JS_BIN_insertBin( parentItem->GetOffset() + parentItem->GetHeaderSize() + parentItem->GetLength(), &binItem, &binBer );
    ber_model->resizeParentHeader( nDiffLen, ber_item_, indexList );

    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binItem );
    if( ret == 0 ) QDialog::accept();
}

void EditValueDlg::changeValueText()
{
    QString strValue = mValueText->toPlainText();
    int nLen = getDataLen( mValueTypeCombo->currentText(), strValue );
    mValueLenText->setText( QString("%1").arg(nLen));
}

void EditValueDlg::changeValueType(int index)
{
    changeValueText();
}
