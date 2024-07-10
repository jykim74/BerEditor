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
    BIN binTTLV = berApplet->getTTLV();

    if( pItem == NULL ) return;

    mTagText->setText( pItem->getTagHex() );
    mTypeText->setText( pItem->getTypeHex() );
    mLengthText->setText( pItem->getLengthHex() );
    mValueText->setPlainText( pItem->getValueHex( &binTTLV ) );
}

void EditTTLVDlg::changeValue()
{
    int nLen = mValueText->toPlainText().length() / 2;
    mValueLenText->setText(QString("%1").arg( nLen ));
}

void EditTTLVDlg::clickOK()
{
    int     ret = 0;

    BIN     srcTag = {0,0};
    BIN     srcType = {0,0};
    BIN     srcLength = {0,0};
    BIN     srcValue = {0,0};
    BIN TTLV = berApplet->getTTLV();

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();

    JS_BIN_decodeHex( mTagText->text().toStdString().c_str(), &srcTag );
    JS_BIN_decodeHex( mTypeText->text().toStdString().c_str(), &srcType );
    JS_BIN_decodeHex( mLengthText->text().toStdString().c_str(), &srcLength );
    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &srcValue );

    if( pItem->getLengthInt() != JS_BIN_int( &srcLength ))
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
