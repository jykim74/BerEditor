#include "edit_value_dlg.h"
#include "ber_item.h"
#include "js_bin.h"
#include "ber_model.h"
#include "ber_applet.h"


EditValueDlg::EditValueDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
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

void EditValueDlg::accept()
{
    BIN binNewVal = {0,0};

    BerModel *ber_model = (BerModel *)ber_item_->model();
    BIN& binBer = ber_model->getBer();

    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binNewVal );
    if( binNewVal.nLen != ber_item_->GetLength() )
    {
        berApplet->warningBox( tr("The changed lengh have to be the same of the original value"), this );
        JS_BIN_reset(&binNewVal);
        return;
    }

    memcpy( &binBer.pVal[ber_item_->GetOffset() + ber_item_->GetHeaderSize()], binNewVal.pVal, binNewVal.nLen );
    ber_item_->setText( ber_item_->GetInfoString( &binBer ));

    JS_BIN_reset( &binNewVal );
    QDialog::accept();
}
