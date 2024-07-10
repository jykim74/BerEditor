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

    int nType = pRootItem->getType();

    if( nType == 0x01 ) // In case of structure
    {
        ret = parseConstruct( 8, pRootItem );
    }

    return 0;
}

int TTLVTreeModel::parseConstruct( int offset, TTLVTreeItem *pParentItem )
{
    int         ret = 0;
    int         next_offset = 0;
    int         bStructed = 0;
    int         start_offset = offset;
    int         level = pParentItem->getLevel() + 1;

    if( binTTLV_.nLen <= offset ) return -1;

    do {
        TTLVTreeItem *pItem = new TTLVTreeItem();
        pItem->setOffset( offset );
        pItem->setLevel( level );

        next_offset = getItem( offset, pItem );

        pItem->setText( pItem->getTitle( &binTTLV_ ) );
        pParentItem->appendRow( pItem );

        if( pItem->getType() == 0x01 )
            bStructed = 1;
        else
            bStructed = 0;

        if( bStructed )
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
    if( pTTLV == NULL )
        JS_BIN_reset( &binTTLV_ );
    else {
        JS_BIN_copy( &binTTLV_, pTTLV );
    }
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

int TTLVTreeModel::resizeParentHeader( int nDiffLen, const TTLVTreeItem *pItem, QModelIndexList &indexList )
{
    if( pItem == NULL ) return -1;

    if( nDiffLen == 0 ) return 0;

    TTLVTreeItem *pParent = (TTLVTreeItem *)pItem->parent();

    while( pParent )
    {
        int nOldLen = 0;
        int nOldHeaderLen = 0;
        BIN binHeader = {0,0};

        int nReLen = pParent->getLengthInt();
        nReLen = nReLen + nDiffLen;
        pParent->setLength( nReLen );

        indexList.append( pParent->index() );
        pParent->getHeader( &binHeader );

        JS_BIN_modifyBin( pParent->getOffset(), &binHeader, &binTTLV_ );
        JS_BIN_reset( &binHeader );

        pParent = (TTLVTreeItem *)pParent->parent();
    }

    return 0;
}
