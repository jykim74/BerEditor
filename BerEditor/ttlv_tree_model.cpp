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

//    pRootItem->setText( pRootItem->getTagHex() );
    pRootItem->setText( pRootItem->getTitle());

    BIN *pType = pRootItem->getType();

    if( pType && pType->pVal[0] == 0x01 ) // In case of structure
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

    BIN     TTLV = {0,0};
    JS_BIN_copy( &TTLV, &binTTLV_ );

    if( TTLV.nLen <= offset ) return -1;

    do {
        TTLVTreeItem *pItem = new TTLVTreeItem();
        pItem->setOffset( offset );
        pItem->setLevel( level );

        next_offset = getItem( offset, pItem );

//        pItem->setText( pItem->getTagHex() );
        pItem->setText( pItem->getTitle() );
        pParentItem->appendRow( pItem );

        if( pItem->getTypeHex() == "01" )
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
    } while ( next_offset > 0 && next_offset < TTLV.nLen );

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
    int     position = 0;
    int     length = 0;
    int     pad = 0;

    BIN     TTLV = {0,0};
    JS_BIN_copy( &TTLV, &binTTLV_ );

    if( TTLV.nLen <= 0 ) return -1;

    pItem->dataReset();

    BIN *pTag = pItem->getTag();
    BIN *pType = pItem->getType();
    BIN *pLength = pItem->getLength();
    BIN *pValue = pItem->getValue();

    JS_BIN_set( pTag, TTLV.pVal + offset, 3 );
    JS_BIN_set( pType, TTLV.pVal + offset + 3, 1 );
    JS_BIN_set( pLength, TTLV.pVal + offset + 4, 4 );
    JS_BIN_set( pValue, TTLV.pVal + offset + 8, pItem->getLengthInt() );

    length = pItem->getLengthInt();

    pad = 8 - (length % 8);
    if( pad == 8 ) pad = 0;

    next_offset = offset + 8 + length + pad;
    return next_offset;
}
