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
    mModifyBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
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

    if( pItem->isStructure() == true )
    {
        mValueText->setReadOnly( true );
        mValueText->setStyleSheet( kReadOnlyStyle );
        mModifyBtn->hide();
        mCancelBtn->setDefault(true);
    }
    else
    {
        mValueText->setReadOnly( false );
        mModifyBtn->show();
    }
}

void EditTTLVDlg::changeValue()
{
    QString strValue = mValueText->toPlainText();

    QString strLen = getDataLenString( DATA_HEX, strValue );
    mValueLenText->setText(QString("%1").arg( strLen ));

    makeHeader();
}

void EditTTLVDlg::changeTTLV()
{
    QString strTTLV = mTTLVText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strTTLV );
    mTTLVLenText->setText( QString("%1").arg( strLen ));
}

QString EditTTLVDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    int ret = getBINFromString( &binData, DATA_HEX, strValue );
    if( ret < 0 )
    {
        berApplet->formatWarn( ret, this);
        return "";
    }

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

    BIN     binValue = {0,0};

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to modify it?" ), this, false );
    if( bVal == false ) return;

    TTLVTreeModel *pModel = (TTLVTreeModel *)pItem->model();

    JS_BIN_decodeHex( mValueText->toPlainText().toStdString().c_str(), &binValue );
    ret = pModel->modifyItem( pItem, &binValue );
    JS_BIN_reset( &binValue );

    if( ret == 0 )
    {
        QDialog::accept();
    }
}

void EditTTLVDlg::clickAdd()
{
    int ret = 0;
    BIN binData = {0,0};
    QString strData;

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), this, false );
    if( bVal == false ) return;

    TTLVTreeItem *pParentItem = (TTLVTreeItem *)pItem->parent();
    if( pParentItem == NULL )
    {
        berApplet->warningBox( tr( "Top-level item cannot be added."), this );
        return;
    }

    TTLVTreeModel *pModel = (TTLVTreeModel *)pItem->model();
    strData = getData();

    JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

    ret = pModel->addItem( pParentItem, &binData );
    JS_BIN_reset( &binData );

    if( ret == 0 ) accept();
}

void EditTTLVDlg::clickDelete()
{
    int ret = 0;

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to delete it?" ), this, false );
    if( bVal == false ) return;

    TTLVTreeItem *pParentItem = (TTLVTreeItem *)pItem->parent();
    if( pParentItem == NULL )
    {
        berApplet->warningBox( tr( "Top-level item cannot be added."), this );
        return;
    }

    TTLVTreeModel *pModel = (TTLVTreeModel *)pItem->model();

    ret = pModel->removeItem( pItem );
    if( ret == 0 ) accept();
}
