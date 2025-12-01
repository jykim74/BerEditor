#include <QFileDialog>

#include "kmip.h"
#include "js_kms.h"

#include "ttlv_tree_model.h"
#include "ttlv_tree_item.h"
#include "ttlv_tree_view.h"

#include "mainwindow.h"
#include "ber_applet.h"

TTLVTreeModel::TTLVTreeModel( QObject *parent )
    : QStandardItemModel( parent )
{
    memset( &binTTLV_, 0x00, sizeof(BIN));
}

TTLVTreeModel::~TTLVTreeModel()
{
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

//    pRootItem->setText( pRootItem->getTitle( &binTTLV_ ));

    if( pRootItem->isStructure() ) // In case of structure
    {
        ret = parseConstruct( 8, pRootItem );
    }

    return 0;
}

int TTLVTreeModel::parseConstruct( int offset, TTLVTreeItem *pParentItem )
{
    int         ret = 0;
    int         next_offset = 0;
    int         start_offset = offset;
    int         level = pParentItem->getLevel() + 1;

    if( binTTLV_.nLen == offset ) return 0;

    if( binTTLV_.nLen < offset ) return -1;

    do {
        TTLVTreeItem *pItem = new TTLVTreeItem();
        pItem->setOffset( offset );
        pItem->setLevel( level );

        next_offset = getItem( offset, pItem );

//        pItem->setText( pItem->getTitle( &binTTLV_ ) );
        pParentItem->appendRow( pItem );

        if( pItem->isStructure() )
        {
            parseConstruct( offset + 8, pItem );
        }

        offset = next_offset;

        if( offset >= (pParentItem->getOffset() + 8 + pParentItem->getLengthInt()) )
            break;
    } while ( next_offset > 0 && next_offset < binTTLV_.nLen );

    return 0;
}

void TTLVTreeModel::setTTLV( const BIN *pTTLV )
{
    JS_BIN_reset( &binTTLV_ );

    if( pTTLV != NULL ) JS_BIN_copy( &binTTLV_, pTTLV );
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

    if( binTTLV_.nLen <= 0 ) return -1;

    pItem->dataReset();
    pItem->setHeader( &pTTLV->pVal[offset], JS_TTLV_HEADER_SIZE );
    pItem->setOffset( offset );

    length = pItem->getLengthInt();

    pad = 8 - (length % 8);
    if( pad == 8 ) pad = 0;

    pItem->setText( pItem->getTitle( &binTTLV_ ));

    next_offset = offset + 8 + length + pad;
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
    TTLVTreeView viewTree = berApplet->mainWindow()->ttlvTree();
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
        pCurItem = viewTree.getNext( (TTLVTreeItem *)pItem );
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

        pCurItem = viewTree.getNext( pCurItem );
    }

    return nullptr;
}

const TTLVTreeItem* TTLVTreeModel::findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    TTLVTreeView viewTree = berApplet->mainWindow()->berTree();
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
        pCurItem = viewTree.getPrev( (TTLVTreeItem *)pItem );
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

        pCurItem = viewTree.getPrev( pCurItem );
    }

    return nullptr;
}


const TTLVTreeItem* TTLVTreeModel::findNextItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BIN binCurHeader = {0,0};

    TTLVTreeView viewTree = berApplet->mainWindow()->berTree();
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
        pCurItem = viewTree.getNext( (TTLVTreeItem *)pItem );
    }

    while( pCurItem )
    {
        binCurHeader.pVal = binTTLV_.pVal + pCurItem->getOffset();
        binCurHeader.nLen = JS_TTLV_HEADER_SIZE;

        if( JS_BIN_cmp( &binCurHeader, pHeader ) == 0 )
        {
            if( pValue == NULL || pValue->nLen <= 0 )
                return pCurItem;

            if( pCurItem->isStructure() == false )
            {
                if( JS_BIN_cmp( &binCurHeader, pHeader ) == 0 )
                {
                    if( pValue == NULL || pValue->nLen == 0 ) return pCurItem;

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
        }

        pCurItem = viewTree.getNext( pCurItem );
    }

    return nullptr;
}

const TTLVTreeItem* TTLVTreeModel::findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BIN binCurHeader = {0,0};

    TTLVTreeView viewTree = berApplet->mainWindow()->berTree();
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
        pCurItem = viewTree.getPrev( (TTLVTreeItem *)pItem );
    }

    while( pCurItem )
    {
        binCurHeader.pVal = binTTLV_.pVal + pCurItem->getOffset();
        binCurHeader.nLen = JS_TTLV_HEADER_SIZE;

        if( JS_BIN_cmp( &binCurHeader, pHeader ) == 0 )
        {
            if( pValue == NULL || pValue->nLen <= 0 )
                return pCurItem;

            if( pCurItem->isStructure() == false )
            {
                if( JS_BIN_cmp( &binCurHeader, pHeader ) == 0 )
                {
                    if( pValue == NULL || pValue->nLen == 0 ) return pCurItem;

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
        }

        pCurItem = pCurItem = viewTree.getPrev( pCurItem );
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
