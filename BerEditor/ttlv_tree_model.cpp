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

    pRootItem->setText( pRootItem->getTitle( &binTTLV_ ));

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

        pItem->setText( pItem->getTitle( &binTTLV_ ) );
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
    int     next_offset = 0;
    int     length = 0;
    int     pad = 0;

    if( binTTLV_.nLen <= 0 ) return -1;

    pItem->dataReset();
    pItem->setHeader( &binTTLV_.pVal[offset], JS_TTLV_HEADER_SIZE );

    length = pItem->getLengthInt();

    pad = 8 - (length % 8);
    if( pad == 8 ) pad = 0;

    next_offset = offset + 8 + length + pad;
    return next_offset;
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
        pParent->setLength( nReLen );

        pParent->getHeader( &binHeader );

        JS_BIN_modifyBin( pParent->getOffset(), &binHeader, pTTLV );
        JS_BIN_reset( &binHeader );

        pParent = (TTLVTreeItem *)pParent->parent();
    }

    return 0;
}

int TTLVTreeModel::addItem( TTLVTreeItem* pParentItem, const BIN *pData )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    int nStart = 0;
    int nOrgLen = 0;

    if( pParentItem == NULL ) return -1;

    JS_BIN_copy( &binMod, &binTTLV_ );

    nStart = pParentItem->getOffset();
    nStart += pParentItem->getLengthTTLV();

    nOrgLen = pParentItem->getLengthInt();
    pParentItem->setLength( nOrgLen + pData->nLen );

    pParentItem->getHeader( &binHeader );
    JS_BIN_modifyBin( pParentItem->getOffset(), &binHeader, &binMod );

    ret = JS_BIN_insertBin( nStart, pData, &binMod );
    if( ret != 0 ) goto end;

    ret = resizeParentHeader( pData->nLen, pParentItem, &binMod );
    if( ret != 0 ) goto end;

    setTTLV( &binMod );

end :
    if( ret != 0 ) pParentItem->setLength( nOrgLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );

    return ret;
}

int TTLVTreeModel::removeItem( TTLVTreeItem *pItem )
{
    int ret = 0;
    int nDiffLen = 0;
    BIN binMod = {0,0};

    if( pItem == NULL ) return -1;
    JS_BIN_copy( &binMod, &binTTLV_ );

    nDiffLen = pItem->getLengthTTLV();

    ret = JS_BIN_removeBin( pItem->getOffset(), nDiffLen, &binMod );
    if( ret != 0 ) goto end;

    ret = resizeParentHeader( -nDiffLen, pItem, &binMod );
    if( ret != 0 ) goto end;

    setTTLV( &binMod );

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

    ret = JS_BIN_modifyBin( pItem->getOffset(), &binHeader, &binMod );
    if( ret != 0 ) goto end;

    JS_BIN_copy( &binNewValue, pValue );
    JS_BIN_appendCh( &binNewValue, 0x00, nNewPadLen - nNewLen );

    ret = JS_BIN_changeBin( pItem->getOffset() + JS_TTLV_HEADER_SIZE, nOrgPadLen, &binNewValue, &binMod );
    if( ret != 0 ) goto end;

    ret = resizeParentHeader( nDiffLen, pItem, &binMod );
    if( ret != 0 ) goto end;

    setTTLV( &binMod );

end :
    if( ret != 0 ) pItem->setLength( nOrgLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binChange );
    JS_BIN_reset( &binNewValue );

    return ret;
}
