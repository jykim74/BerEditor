#include "edit_ttlv_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "ttlv_tree_item.h".h"

#include "js_bin.h"

EditTTLVDlg::EditTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));

    initialize();
}

EditTTLVDlg::~EditTTLVDlg()
{

}

void EditTTLVDlg::initialize()
{
    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();

    if( pItem == NULL ) return;

    mTagText->setText( pItem->getTagHex() );
    mTypeText->setText( pItem->getTypeHex() );
    mLengthText->setText( pItem->getLengthHex() );
    mValueText->setPlainText( pItem->getValueHex() );
}

void EditTTLVDlg::changeValue()
{
    int nLen = mValueText->toPlainText().length() / 2;
    mValueLenText->setText(QString("%1").arg( nLen ));
}

void EditTTLVDlg::clickOK()
{
    int     ret = 0;
    BIN     *pDstTag = NULL;
    BIN     *pDstType = NULL;
    BIN     *pDstLength = NULL;
    BIN     *pDstValue = NULL;

    BIN     srcTag = {0,0};
    BIN     srcType = {0,0};
    BIN     srcLength = {0,0};
    BIN     srcValue = {0,0};
    BIN TTLV = berApplet->mainWindow()->ttlvModel()->getTTLV();

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    pDstTag = pItem->getTag();
    pDstType = pItem->getType();
    pDstLength = pItem->getLength();
    pDstValue = pItem->getValue();

    JS_BIN_decodeHex( mTagText->text().toStdString().c_str(), &srcTag );
    JS_BIN_decodeHex( mTypeText->text().toStdString().c_str(), &srcType );
    JS_BIN_decodeHex( mLengthText->text().toStdString().c_str(), &srcLength );
    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &srcValue );

    if( pDstTag->nLen != srcTag.nLen
            || pDstType->nLen != srcType.nLen
            || pDstLength->nLen != srcLength.nLen
            || pDstValue->nLen != srcValue.nLen )
    {
        berApplet->warningBox( "All length of value have to be the same with orginal length value." );
        ret = -1;
    }

    int nOffset = pItem->getOffset();

    memcpy( &TTLV.pVal[nOffset], srcTag.pVal, srcTag.nLen );
    nOffset += srcTag.nLen;

    memcpy( &TTLV.pVal[nOffset], srcType.pVal, srcType.nLen );
    nOffset += srcType.nLen;

    memcpy( &TTLV.pVal[nOffset], srcLength.pVal, srcLength.nLen );
    nOffset += srcLength.nLen;

    memcpy( &TTLV.pVal[nOffset], srcValue.pVal, srcValue.nLen );
    nOffset += srcValue.nLen;

    JS_BIN_reset( &srcTag );
    JS_BIN_reset( &srcType );
    JS_BIN_reset( &srcLength );
    JS_BIN_reset( &srcValue );

    if( ret == 0 )
    {
        berApplet->mainWindow()->ttlvModel()->parseTree();

        QDialog::accept();
    }
}
