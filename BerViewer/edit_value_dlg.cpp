#include "edit_value_dlg.h"
#include "ber_item.h"
#include "js_bin.h"
#include "ber_model.h"
#include "ber_applet.h"


EditValueDlg::EditValueDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(runAdd()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(runDelete()));
    connect( mModifyBtn, SIGNAL(clicked()), this, SLOT(runChange()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValueText()));

    mCloseBtn->setFocus();
}

EditValueDlg::~EditValueDlg()
{

}

void EditValueDlg::setItem(BerItem *pItem)
{
    BIN binHeader = {0,0};
    BIN binValue = {0,0};
    char *pHeader = NULL;
    char *pValue = NULL;

    ber_item_ = pItem;
    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();

    ber_item_ = pItem;
    mClassText->setText( ber_item_->GetClassString() );
    mTagText->setText( ber_item_->GetTagString() );

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

    JS_BIN_set( &binValue, &binBer.pVal[ber_item_->GetOffset() + ber_item_->GetHeaderSize()], ber_item_->GetLength() );
    JS_BIN_encodeHex( &binValue, &pValue );
    mValueText->setPlainText( pValue );

    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binValue );
    if( pHeader ) JS_free( pHeader );
    if( pValue ) JS_free( pValue );
}

#if 0
void EditValueDlg::runChange()
{
    int nDiffLen = 0;

    BIN binNewVal = {0,0};
    BIN binHeader = {0,0};

    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();

    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binNewVal );
    if( binNewVal.nLen != ber_item_->GetLength() )
    {
        berApplet->warningBox( tr("The changed lengh have to be the same of the original value"), this );
        JS_BIN_reset(&binNewVal);
        return;
    }

//    memcpy( &binBer.pVal[ber_item_->GetOffset() + ber_item_->GetHeaderSize()], binNewVal.pVal, binNewVal.nLen );

    ber_item_->changeLength( binNewVal.nLen, &nDiffLen );
    ber_item_->getHeaderBin( &binHeader );

    JS_BIN_changeBin( ber_item_->GetOffset() + ber_item_->GetHeaderSize(), ber_item_->GetLength(), &binNewVal, &binBer );

    ber_item_->setText( ber_item_->GetInfoString( &binBer ));

    JS_BIN_reset( &binNewVal );
    JS_BIN_reset( &binHeader );

    QDialog::accept();
}
#else
void EditValueDlg::runChange()
{
    int ret = 0;
    int nDiffLen = 0;
    int nOrgLen = 0;
    int nOrgHeaderLen = 0;

    BIN binNewVal = {0,0};
    BIN binHeader = {0,0};
    BIN binNewItem = {0,0};

    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();
    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binNewVal );

    nOrgLen = ber_item_->GetLength();
    nOrgHeaderLen = ber_item_->GetHeaderSize();

    ber_item_->changeLength( binNewVal.nLen, &nDiffLen );
    ber_item_->getHeaderBin( &binHeader );
    JS_BIN_copy( &binNewItem, &binHeader );
    JS_BIN_appendBin( &binNewItem, &binNewVal );

    ret = JS_BIN_changeBin( ber_item_->GetOffset(), nOrgHeaderLen + nOrgLen, &binNewItem, &binBer );

    if( nDiffLen != 0 )
    {
        BerItem *parentItem = (BerItem *)ber_item_->parent();

        while( parentItem )
        {
            BIN binPHeader = {0,0};

            nOrgLen = parentItem->GetLength();
            nOrgHeaderLen = parentItem->GetHeaderSize();

            parentItem->changeLength( nOrgLen + nDiffLen, &nDiffLen );

            if( nDiffLen == 0 ) break;

            parentItem->getHeaderBin( &binPHeader );
            JS_BIN_changeBin( parentItem->GetOffset(), nOrgHeaderLen, &binPHeader, &binBer );
            JS_BIN_reset( &binPHeader );

            parentItem = (BerItem *)parentItem->parent();
        }
    }

    JS_BIN_reset( &binNewVal );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binNewItem );

    if( ret == 0 ) QDialog::accept();
}
#endif

void EditValueDlg::runDelete()
{
    int ret = 0;
    int nDiffLen = 0;
    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();

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


    if( nDiffLen > 0 )
    {
        int nRemoveLen = -nDiffLen;
        parentItem = (BerItem *)ber_item_->parent();

        while( parentItem )
        {
            int nOrgLen = 0;
            int nOrgHeaderLen = 0;
            BIN binPHeader = {0,0};

            nOrgLen = parentItem->GetLength();
            nOrgHeaderLen = parentItem->GetHeaderSize();

            parentItem->changeLength( nOrgLen + nRemoveLen, &nRemoveLen );

            if( nDiffLen == 0 ) break;

            parentItem->getHeaderBin( &binPHeader );
            JS_BIN_changeBin( parentItem->GetOffset(), nOrgHeaderLen, &binPHeader, &binBer );
            JS_BIN_reset( &binPHeader );

            parentItem = (BerItem *)parentItem->parent();
        }
    }

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


    if( parentItem == NULL )
    {
        berApplet->warningBox( QString( "Root Item can not be added."), this );
        QDialog::reject();
        return;
    }

    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binVal );

    ber_item_->changeLength( binVal.nLen, &nDiffLen );
    nDiffLen = ber_item_->GetHeaderSize();
    nDiffLen += ber_item_->GetLength();

    JS_BIN_set( &binItem, ber_item_->GetHeader(), ber_item_->GetHeaderSize() );
    JS_BIN_appendBin( &binItem, &binVal );

    JS_BIN_insertBin( parentItem->GetOffset() + parentItem->GetHeaderSize() + parentItem->GetLength(), &binItem, &binBer );

    if( nDiffLen > 0 )
    {
        parentItem = (BerItem *)ber_item_->parent();

        while( parentItem )
        {
            int nOrgLen = 0;
            int nOrgHeaderLen = 0;
            BIN binPHeader = {0,0};

            nOrgLen = parentItem->GetLength();
            nOrgHeaderLen = parentItem->GetHeaderSize();

            parentItem->changeLength( nOrgLen + nDiffLen, &nDiffLen );

            if( nDiffLen == 0 ) break;

            parentItem->getHeaderBin( &binPHeader );
            JS_BIN_changeBin( parentItem->GetOffset(), nOrgHeaderLen, &binPHeader, &binBer );
            JS_BIN_reset( &binPHeader );

            parentItem = (BerItem *)parentItem->parent();
        }
    }

    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binItem );
    if( ret == 0 ) QDialog::accept();
}

void EditValueDlg::changeValueText()
{
    int nLen = mValueText->toPlainText().length() / 2;
    mValueLenText->setText( QString("%1").arg(nLen));
}
