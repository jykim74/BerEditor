#include "edit_ttlv_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "ttlv_tree_item.h"
#include "common.h"

#include "js_kms.h"
#include "js_bin.h"

EditTTLVDlg::EditTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mModifyBtn, SIGNAL(clicked()), this, SLOT(clickModify()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(clickDelete()));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));
    connect( mTTLVText, SIGNAL(textChanged()), this, SLOT(changeTTLV()));

    initialize();
    mCancelBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize( width(), minimumSizeHint().height());
}

EditTTLVDlg::~EditTTLVDlg()
{

}

void EditTTLVDlg::initialize()
{
    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    BIN binTTLV = berApplet->getTTLV();

    if( pItem == NULL ) return;

    QString strTag = pItem->getTagHex();
    int nTag = strTag.toInt( nullptr, 16 );
    QString strType = pItem->getTypeHex();
    int nType = strType.toInt( nullptr, 16 );

    mTagText->setText( strTag );
    mTagNameText->setText( JS_KMS_tagName( nTag ) );
    mTypeText->setText( strType );
    mTypeNameText->setText( JS_KMS_typeName( nType ));

    mLengthText->setText( pItem->getLengthHex() );
    mValueText->setPlainText( pItem->getValueHex( &binTTLV ) );
}

void EditTTLVDlg::changeValue()
{
    int nLen = mValueText->toPlainText().length() / 2;
    mValueLenText->setText(QString("%1").arg( nLen ));

    makeHeader();
}

void EditTTLVDlg::changeTTLV()
{
    QString strTTLV = mTTLVText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strTTLV );
    mTTLVLenText->setText( QString("%1").arg( nLen ));
}

QString EditTTLVDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    getBINFromString( &binData, DATA_HEX, strValue );

    int nAppend = 8 - binData.nLen % 8;
    if( nAppend > 0 && nAppend != 8 ) JS_BIN_appendCh( &binData, 0x00, nAppend );

    strData = mHeaderText->text();
    strData += getHexString( &binData );

    JS_BIN_reset( &binData );

    return strData.toUpper();
}

void EditTTLVDlg::makeHeader()
{
    QString strTag = mTagText->text();
    QString strValue = mValueText->toPlainText();

    if( strTag.length() < 6 ) return;

    int nType = mTypeText->text().toInt( nullptr, 16 );
    int nLen = getDataLen( DATA_HEX, strValue );


    QString strHeader = QString( "%1%2%3" )
                            .arg( strTag )
                            .arg( nType, 2, 16, QLatin1Char('0') )
                            .arg( nLen, 8, 16, QLatin1Char('0') );

    mHeaderText->setText( strHeader.toUpper() );
    mTTLVText->setPlainText( getData() );
}

void EditTTLVDlg::clickModify()
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

void EditTTLVDlg::clickAdd()
{

}

void EditTTLVDlg::clickDelete()
{

}
