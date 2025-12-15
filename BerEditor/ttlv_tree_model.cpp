#include <QFileDialog>
#include <QHeaderView>
#include <QClipboard>
#include <QGuiApplication>

#include "kmip.h"
#include "js_kms.h"

#include "ttlv_tree_model.h"
#include "ttlv_tree_item.h"
#include "ttlv_tree_view.h"

#include "mainwindow.h"
#include "ber_applet.h"
#include "edit_ttlv_dlg.h"
#include "make_ttlv_dlg.h"

TTLVTreeModel::TTLVTreeModel( QObject *parent )
    : QStandardItemModel( parent )
{
    ttlv_view_ = new TTLVTreeView;
    ttlv_view_->setModel( this );

    ttlv_view_->header()->setVisible( false );

    memset( &binTTLV_, 0x00, sizeof(BIN));
}

TTLVTreeModel::~TTLVTreeModel()
{
    if( ttlv_view_ ) delete ttlv_view_;

    JS_BIN_reset( &binTTLV_ );
}

int TTLVTreeModel::parseTree()
{
    int     ret = 0;
    int     offset = 0;

    TTLVTreeItem  *pRootItem = new TTLVTreeItem();

    clear();

    pRootItem->setOffset(offset);
    pRootItem->setLevel(0);

    offset = getItem( offset, pRootItem );
    insertRow( 0, pRootItem );

    if( pRootItem->isStructure() ) // In case of structure
    {
        ret = parseConstruct( pRootItem );
    }

    ttlv_view_->viewRoot();
    return 0;
}

int TTLVTreeModel::parseConstruct( TTLVTreeItem *pParentItem )
{
    int         ret = 0;
    int         offset = 0;
    int         next_offset = 0;
    int         start_offset = offset;
    int         level = pParentItem->getLevel() + 1;

    if( pParentItem == NULL ) return JSR_ERR;
    start_offset = pParentItem->getOffset() + JS_TTLV_HEADER_SIZE;

    offset = start_offset;
    if( binTTLV_.nLen <= offset ) return JSR_TTLV_BAD_OFFSET;

    do {
        TTLVTreeItem *pItem = new TTLVTreeItem();
        pItem->setOffset( offset );
        pItem->setLevel( level );

        next_offset = getItem( offset, pItem );
        if( next_offset < 0 ) return JSR_ERR3;

        pParentItem->appendRow( pItem );

        if( pItem->isStructure() )
        {
            ret = parseConstruct( pItem );
            if( ret != JSR_OK ) return ret;
        }

        offset = next_offset;

        if( offset >= (pParentItem->getOffset() + 8 + pParentItem->getLengthInt()) )
            break;
    } while ( next_offset > 0 && next_offset < binTTLV_.nLen );

    ret = JSR_OK;
    return ret;
}

void TTLVTreeModel::setTTLV( const BIN *pTTLV )
{
    JS_BIN_reset( &binTTLV_ );

    if( pTTLV != NULL ) JS_BIN_copy( &binTTLV_, pTTLV );
}

void TTLVTreeModel::setCurrentItem( const TTLVTreeItem *pItem )
{
    if( pItem == NULL ) return;

    ttlv_view_->expandToTop( pItem );
    QModelIndex idx = pItem->index();
    ttlv_view_->clicked( idx );
    ttlv_view_->setCurrentIndex( idx );
}

TTLVTreeItem* TTLVTreeModel::currentItem()
{
    return ttlv_view_->currentItem();
}

int TTLVTreeModel::getItem( int offset, TTLVTreeItem *pItem )
{
    return getItem( &binTTLV_, offset, pItem );
}

int TTLVTreeModel::getItem( BIN *pTTLV, int offset, TTLVTreeItem *pItem )
{
    int     next_offset = 0;
    int     length = 0;
    int     pad = 0;

    if( binTTLV_.nLen <= 0 ) return JSR_ERR;

    pItem->dataReset();
    pItem->setHeader( &pTTLV->pVal[offset], JS_TTLV_HEADER_SIZE );
    pItem->setOffset( offset );

    length = pItem->getLengthInt();

    pad = 8 - (length % 8);
    if( pad == 8 ) pad = 0;

    pItem->setText( pItem->getTitle( &binTTLV_ ));

    next_offset = offset + JS_TTLV_HEADER_SIZE + length + pad;
    return next_offset;
}

void TTLVTreeModel::getTablePosition( int nOffset, int *pRow, int *pCol )
{
    if( nOffset < 0 ) return;

    int nRow = int( nOffset / 16 );
    int nCol = ( nOffset % 16) + 1;

    *pRow = nRow;
    *pCol = nCol;
}

int TTLVTreeModel::resizeParentHeader( int nDiffLen, const TTLVTreeItem *pItem, BIN *pTTLV )
{
    if( pItem == NULL ) return -1;

    if( nDiffLen == 0 ) return 0;

    TTLVTreeItem *pParent = (TTLVTreeItem *)pItem->parent();

    while( pParent )
    {
        BIN binHeader = {0,0};

        int nReLen = pParent->getLengthInt();
        nReLen = nReLen + nDiffLen;
        if( nReLen < 0 ) nReLen = 0;
        pParent->setLength( nReLen );

        pParent->getHeader( &binHeader );

        JS_BIN_modifyBin( pTTLV, pParent->getOffset(), &binHeader );
        JS_BIN_reset( &binHeader );

        pParent = (TTLVTreeItem *)pParent->parent();
    }

    return 0;
}

const TTLVTreeItem* TTLVTreeModel::addItem( TTLVTreeItem* pParentItem, bool bFirst, const BIN *pData )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    int nStart = 0;
    int nOrgLen = 0;
    TTLVTreeItem *pChild = NULL;

    if( pParentItem == NULL ) return nullptr;

    JS_BIN_copy( &binMod, &binTTLV_ );

    nStart = pParentItem->getOffset();

    if( bFirst == true )
        nStart += JS_TTLV_HEADER_SIZE;
    else
        nStart += pParentItem->getLengthTTLV();

    nOrgLen = pParentItem->getLengthInt();
    pParentItem->setLength( nOrgLen + pData->nLen );

    pParentItem->getHeader( &binHeader );
    JS_BIN_modifyBin( &binMod, pParentItem->getOffset(), &binHeader );

    ret = JS_BIN_insertBin( &binMod, nStart, pData );
    if( ret != 0 ) goto end;

    resizeParentHeader( pData->nLen, pParentItem, &binMod );

    setTTLV( &binMod );
    pChild = new TTLVTreeItem;
    getItem( nStart, pChild );
    pChild->setLevel( pParentItem->getLevel() + 1 );

    if( bFirst == true )
        pParentItem->insertRow( 0, pChild );
    else
        pParentItem->appendRow( pChild );

end :
    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );

    return pChild;
}

int TTLVTreeModel::removeItem( TTLVTreeItem *pItem )
{
    int ret = 0;
    int nDiffLen = 0;
    BIN binMod = {0,0};
    TTLVTreeItem *pParent = NULL;

    if( pItem == NULL ) return JSR_ERR;
    if( pItem->parent() == NULL ) return JSR_ERR2;

    JS_BIN_copy( &binMod, &binTTLV_ );

    nDiffLen = pItem->getLengthTTLV();

    ret = JS_BIN_removeBin( &binMod, pItem->getOffset(), nDiffLen );
    if( ret != 0 ) goto end;

    pParent = (TTLVTreeItem *)pItem->parent();

    resizeParentHeader( -nDiffLen, pItem, &binMod );
    setTTLV( &binMod );

    if( pParent )
    {
        int count = pParent->rowCount();
        for( int i = 0; i < count; i++ )
        {
            TTLVTreeItem *curItem = (TTLVTreeItem *)pParent->child( i );
            if( curItem == pItem )
            {
                pParent->removeRow( i );
                break;
            }
        }
    }

end :
    JS_BIN_reset( &binMod );
    return ret;
}

int TTLVTreeModel::modifyItem( TTLVTreeItem *pItem, const BIN *pValue )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    BIN binChange = {0,0};
    BIN binNewValue = {0,0};

    int nOrgLen = 0;
    int nOrgPadLen = 0;
    int nNewLen = 0;
    int nNewPadLen = 0;
    int nLeft = 0;
    int nDiffLen = 0;

    if( pItem == NULL ) return -1;
    JS_BIN_copy( &binMod, &binTTLV_ );

    nOrgLen = pItem->getLengthInt();
    nOrgPadLen = pItem->getLengthWithPad();

    nNewLen = pValue->nLen;

    nLeft = nNewLen % 8;
    if( nLeft > 0 )
        nNewPadLen = nNewLen + 8 - nLeft;
    else
        nNewPadLen = nNewLen;

    nDiffLen = nNewPadLen - nOrgPadLen;

    pItem->setLength( nNewLen );
    pItem->getHeader( &binHeader );

    ret = JS_BIN_modifyBin( &binMod, pItem->getOffset(), &binHeader );
    if( ret != 0 ) goto end;

    JS_BIN_copy( &binNewValue, pValue );
    JS_BIN_appendCh( &binNewValue, 0x00, nNewPadLen - nNewLen );

    ret = JS_BIN_changeBin( &binMod, pItem->getOffset() + JS_TTLV_HEADER_SIZE, nOrgPadLen, &binNewValue );
    if( ret != 0 ) goto end;

    resizeParentHeader( nDiffLen, pItem, &binMod );
    setTTLV( &binMod );

end :
    if( ret != 0 ) pItem->setLength( nOrgLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binChange );
    JS_BIN_reset( &binNewValue );

    return ret;
}

const TTLVTreeItem* TTLVTreeModel::findItemByOffset( TTLVTreeItem* pParentItem, int nOffset )
{
    TTLVTreeItem *pStartItem = NULL;
    const TTLVTreeItem *pFoundItem = NULL;
    if( pParentItem == nullptr )
    {
        QModelIndex idx = index(0,0);
        pStartItem = (TTLVTreeItem *)itemFromIndex( idx );
    }
    else
    {
        pStartItem = pParentItem;
    }

    if( pStartItem == NULL ) return nullptr;

    if( pStartItem->getOffset() == nOffset ) return pStartItem;

    if( pStartItem->getOffset() > nOffset ) return nullptr;

    if( pStartItem->hasChildren() == true )
    {
        int nCount = pStartItem->rowCount();

        for( int i = 0; i < nCount; i++ )
        {
            TTLVTreeItem *pChild = (TTLVTreeItem *)pStartItem->child( i );
            if( pChild->getOffset() > nOffset ) break;

            pFoundItem = findItemByOffset( pChild, nOffset );
            if( pFoundItem != nullptr ) return pFoundItem;
        }
    }

    return nullptr;
}

const TTLVTreeItem* TTLVTreeModel::findNextItemByValue( const TTLVTreeItem* pItem, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};

    TTLVTreeItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (TTLVTreeItem *)item(0,0);
    }
    else
    {
        pCurItem = ttlv_view_->getNext( (TTLVTreeItem *)pItem );
    }

    if( pValue == NULL || pValue->nLen <= 0 ) return pCurItem;

    while( pCurItem )
    {
        if( pCurItem->isStructure() == false )
        {
            binCurValue.pVal = binTTLV_.pVal + pCurItem->getOffset() + JS_TTLV_HEADER_SIZE;
            binCurValue.nLen = pCurItem->getLengthInt();

            if( bMatched == true )
            {
                ret = JS_BIN_cmp( &binCurValue, pValue );
                if( ret == 0 ) return pCurItem;
            }
            else
            {
                ret = JS_BIN_memmem( &binCurValue, pValue );
                if( ret >= 0 ) return pCurItem;
            }
        }

        pCurItem = ttlv_view_->getNext( pCurItem );
    }

    return nullptr;
}

const TTLVTreeItem* TTLVTreeModel::findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};

    TTLVTreeItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (TTLVTreeItem *)item(0,0);
    }
    else
    {
        pCurItem = ttlv_view_->getPrev( (TTLVTreeItem *)pItem );
    }

    if( pValue == NULL || pValue->nLen <= 0 ) return pCurItem;

    while( pCurItem )
    {
        if( pCurItem->isStructure() == false )
        {
            binCurValue.pVal = binTTLV_.pVal + pCurItem->getOffset() + JS_TTLV_HEADER_SIZE;
            binCurValue.nLen = pCurItem->getLengthInt();

            if( bMatched == true )
            {
                ret = JS_BIN_cmp( &binCurValue, pValue );
                if( ret == 0 ) return pCurItem;
            }
            else
            {
                ret = JS_BIN_memmem( &binCurValue, pValue );
                if( ret >= 0 ) return pCurItem;
            }
        }

        pCurItem = ttlv_view_->getPrev( pCurItem );
    }

    return nullptr;
}


const TTLVTreeItem* TTLVTreeModel::findNextItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BIN binCurHeader = {0,0};

    TTLVTreeItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (TTLVTreeItem *)item(0,0);
    }
    else
    {
        pCurItem = ttlv_view_->getNext( (TTLVTreeItem *)pItem );
    }

    while( pCurItem )
    {
        binCurHeader.pVal = binTTLV_.pVal + pCurItem->getOffset();
        binCurHeader.nLen = JS_TTLV_HEADER_SIZE;

        if( JS_BIN_memmem( &binCurHeader, pHeader ) == 0 )
        {
            if( pValue == NULL || pValue->nLen <= 0 )
                return pCurItem;

            if( pCurItem->isStructure() == false )
            {
                binCurValue.pVal = binTTLV_.pVal + pCurItem->getOffset() + JS_TTLV_HEADER_SIZE;
                binCurValue.nLen = pCurItem->getLengthInt();

                if( bMatched == true )
                {
                    ret = JS_BIN_cmp( &binCurValue, pValue );
                    if( ret == 0 ) return pCurItem;
                }
                else
                {
                    ret = JS_BIN_memmem( &binCurValue, pValue );
                    if( ret >= 0 ) return pCurItem;
                }
            }
        }

        pCurItem = ttlv_view_->getNext( pCurItem );
    }

    return nullptr;
}

const TTLVTreeItem* TTLVTreeModel::findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BIN binCurHeader = {0,0};

    TTLVTreeItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (TTLVTreeItem *)item(0,0);
    }
    else
    {
        pCurItem = ttlv_view_->getPrev( (TTLVTreeItem *)pItem );
    }

    while( pCurItem )
    {
        binCurHeader.pVal = binTTLV_.pVal + pCurItem->getOffset();
        binCurHeader.nLen = JS_TTLV_HEADER_SIZE;

        if( JS_BIN_memmem( &binCurHeader, pHeader ) == 0 )
        {
            if( pValue == NULL || pValue->nLen <= 0 )
                return pCurItem;

            if( pCurItem->isStructure() == false )
            {
                binCurValue.pVal = binTTLV_.pVal + pCurItem->getOffset() + JS_TTLV_HEADER_SIZE;
                binCurValue.nLen = pCurItem->getLengthInt();

                if( bMatched == true )
                {
                    ret = JS_BIN_cmp( &binCurValue, pValue );
                    if( ret == 0 ) return pCurItem;
                }
                else
                {
                    ret = JS_BIN_memmem( &binCurValue, pValue );
                    if( ret >= 0 ) return pCurItem;
                }
            }
        }

        pCurItem = pCurItem = ttlv_view_->getPrev( pCurItem );
    }

    return nullptr;
}

void TTLVTreeModel::selectValue( TTLVTreeItem *pItem, const BIN *pValue, bool bPart )
{
    int nStart = 0;
    int nLen = 0;
    if( pItem == NULL) return;

    if( pValue == NULL || pValue->nLen <= 0 ) return;

    BIN binCurValue;
    binCurValue.pVal = binTTLV_.pVal + pItem->getOffset() + JS_TTLV_HEADER_SIZE;
    binCurValue.nLen = pItem->getLengthInt();

    int ret = JS_BIN_memmem( &binCurValue, pValue );
    if( ret < 0 ) return;

    if( bPart == true )
        nStart = JS_TTLV_HEADER_SIZE + ret;
    else
        nStart = pItem->getOffset() + JS_TTLV_HEADER_SIZE + ret;

    nLen = pValue->nLen;

    QTableWidget *pTable = berApplet->mainWindow()->rightTable();

    for( int i = 0; i < nLen; i++ )
    {
        int nRow = 0;
        int nCol = 0;
        getTablePosition( nStart + i, &nRow, &nCol );
        QTableWidgetItem *pTableItem = pTable->item( nRow, nCol );
        pTableItem->setSelected(true);
    }
}

void TTLVTreeModel::CopyAsHex()
{
    char *pHex = NULL;
    BIN binVal = {0,0};

    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), ttlv_view_ );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();

    JS_BIN_set( &binVal, binTTLV_.pVal + item->getOffset(), item->getLengthTTLV() );
    JS_BIN_encodeHex( &binVal, &pHex );
    clipboard->setText(pHex);
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binVal );
}

void TTLVTreeModel::CopyAsBase64()
{
    char *pBase64 = NULL;
    BIN binVal = {0,0};
    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), ttlv_view_ );
        return;
    }

    BIN binTTLV = berApplet->getTTLV();
    QClipboard *clipboard = QGuiApplication::clipboard();

    JS_BIN_set( &binVal, binTTLV_.pVal + item->getOffset(), item->getLengthTTLV() );
    JS_BIN_encodeBase64( &binVal, &pBase64 );
    clipboard->setText(pBase64);
    if( pBase64 ) JS_free(pBase64);
    JS_BIN_reset( &binVal );
}

void TTLVTreeModel::copy()
{
    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), ttlv_view_ );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();

    QString strLog = berApplet->mainWindow()->getInfo();
    clipboard->setText(strLog);
}

void TTLVTreeModel::insertNode()
{
    int ret = 0;
    BIN binData = {0,0};

    TTLVTreeItem* item = currentItem();

    if( item->isStructure() == false )
    {
        berApplet->warningBox( tr( "The item is not structured" ), ttlv_view_ );
        return;
    }

    MakeTTLVDlg makeTTLV;
    makeTTLV.setHeadLabel( tr( "Insert TTLV [ Tag Type Length Value ]" ) );
    ret = makeTTLV.exec();

    if( ret == QDialog::Accepted )
    {
        bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), ttlv_view_, false );
        if( bVal == false ) return;

        QString strData = makeTTLV.getData();
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        bool bFirst = makeTTLV.mFirstSetCheck->isChecked();
        const TTLVTreeItem *pAddItem = (const TTLVTreeItem *)addItem( item, bFirst, &binData );

        JS_BIN_reset( &binData );

        if( pAddItem )
        {
            int nOffset = pAddItem->offset_;
            berApplet->mainWindow()->reloadTTLV();
            const TTLVTreeItem *findItem = findItemByOffset( nullptr, nOffset );
            if( findItem ) setCurrentItem( findItem );
        }
        else
        {
            berApplet->warningBox( tr( "failed to insert" ), ttlv_view_ );
        }
    }
}

void TTLVTreeModel::editNode()
{
    int ret = 0;

    TTLVTreeItem *pItem = currentItem();

    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), ttlv_view_ );
        return;
    }

    EditTTLVDlg editTTLV;
    editTTLV.setHeadLabel( tr( "Edit TTLV [ Tag Type Length Value ]" ) );
    ret = editTTLV.exec();
}

void TTLVTreeModel::deleteNode()
{
    int ret = 0;

    TTLVTreeItem *pItem = currentItem();
    const TTLVTreeItem *pParent = NULL;

    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), ttlv_view_ );
        return;
    }

    if( pItem->parent() == nullptr )
    {
        berApplet->warningBox( tr( "Top-level items cannot be deleted" ), ttlv_view_ );
        return;
    }

    pParent = (TTLVTreeItem *)pItem->parent();

    bool bVal = berApplet->yesOrCancelBox( tr("Are you sure you want to delete it?"), ttlv_view_, true );
    if( bVal == false ) return;

    ret = removeItem( pItem );
    if( ret == JSR_OK )
    {
        int nOffset = pParent->offset_;
        berApplet->mainWindow()->reloadTTLV();

        const TTLVTreeItem *findItem = findItemByOffset( nullptr, nOffset );
        if( findItem ) setCurrentItem( findItem );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete: %1").arg( JERR(ret)), ttlv_view_ );
    }
}

const QString TTLVTreeModel::saveNode()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( ttlv_view_, JS_FILE_TYPE_BIN, strPath );
    if( fileName.length() < 1 ) return "";

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return "";

    BIN binData = {0,0};

    pItem->getDataAll( &binTTLV_, &binData );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binData );

    return fileName;
}

void TTLVTreeModel::saveNodeValue()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( ttlv_view_, JS_FILE_TYPE_BIN, strPath );
    if( fileName.length() < 1 ) return;

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return;

    BIN binData = {0,0};

    pItem->getValueWithPad( &binTTLV_, &binData );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binData );
}
