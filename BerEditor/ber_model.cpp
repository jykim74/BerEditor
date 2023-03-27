#include "ber_item.h"
#include "ber_model.h"
#include "js_bin.h"

#include <QStandardItemModel>

BerModel::BerModel( QObject *parent )
    : QStandardItemModel (parent)
{
    binBer_.nLen = 0;
    binBer_.pVal = 0;

    initialize();
}

void BerModel::initialize()
{
    clear();
    QStringList labels;
//    labels << tr("BER structure");
    setHorizontalHeaderLabels( labels );
}


void BerModel::setBer(const BIN *pBer )
{
    if( pBer == NULL )
        JS_BIN_reset( &binBer_ );
    else {
        JS_BIN_copy( &binBer_, pBer );
    }
}

int BerModel::parseTree()
{
    int ret = 0;
    int offset = 0;

    BerItem *pRootItem = new BerItem();

    clear();
    QStringList labels;
    setHorizontalHeaderLabels( labels );


    pRootItem->SetOffset(offset);
    pRootItem->SetLevel(0);

    offset = getItem( 0, pRootItem );
    insertRow( 0, pRootItem );

    pRootItem->setText( pRootItem->GetInfoString( &binBer_) );

    if( (pRootItem->GetId() & JS_FORM_MASK) == JS_CONSTRUCTED )
    {
        if( pRootItem->GetIndefinite() )
            ret = parseIndefiniteConstruct( pRootItem->GetHeaderSize(), pRootItem );
        else
            ret = parseConstruct( pRootItem->GetHeaderSize(), pRootItem );
    }


    return 0;
}

int BerModel::parseConstruct(int offset, BerItem *pParentItem)
{
    int     ret = 0;
    int     next_offset = 0;
    int     isConstructed = 0;
    int     start_offset = offset;
    int     level = pParentItem->GetLevel() + 1;

    if( offset >= binBer_.nLen ) return -1;

    do {
        BerItem *pItem = new BerItem();
        pItem->SetOffset(offset);
        pItem->SetLevel(level );
        next_offset = getItem( offset, pItem );

        if( next_offset <= 0 ) return -1;

        pItem->setText( pItem->GetInfoString( &binBer_));

        pParentItem->appendRow( pItem );

        if( (pItem->GetId() & JS_FORM_MASK) == JS_CONSTRUCTED )
            isConstructed = 1;
        else {
            isConstructed = 0;
        }

        if( isConstructed )
        {
            if( pItem->GetIndefinite() )
            {
                ret = parseIndefiniteConstruct( offset + pItem->GetHeaderSize(), pItem );
                if( ret <= 0 ) return -1;
                next_offset += ret;
            }
            else
            {
                if( pItem->length_ > 0 ) parseConstruct( offset + pItem->GetHeaderSize(), pItem );

                int end = start_offset + pParentItem->GetLength();
                if( pParentItem->GetTag() == JS_BITSTRING ) end--;

                if( next_offset >= end ) break;
            }
        }

        offset = next_offset;

    } while( next_offset > 0 && next_offset < (start_offset + pParentItem->GetLength()) );

    return 0;
}

int BerModel::parseIndefiniteConstruct( int offset, BerItem *pParentItem )
{
    int     ret = 0;
    int     next_offset = 0;
    int     isConstructed = 0;
    int     start_offset = offset;
    int     level = pParentItem->GetLevel() + 1;
    int     length = -1;

    if( offset >= binBer_.nLen ) return -1;

    do {
        if( offset >= binBer_.nLen ) return -1;

        BerItem *pItem = new BerItem();
        pItem->SetOffset(offset);
        pItem->SetLevel(level );
        next_offset = getItem( offset, pItem );

        pItem->setText( pItem->GetInfoString( &binBer_));
        pParentItem->appendRow( pItem );

        if( (pItem->GetId() & JS_FORM_MASK) == JS_CONSTRUCTED )
            isConstructed = 1;
        else {
            isConstructed = 0;
        }

        if( isConstructed )
        {
            if( pItem->GetIndefinite() )
            {
                ret = parseIndefiniteConstruct( offset + pItem->GetHeaderSize(), pItem );
                if( ret <= 0 ) return -1;
                next_offset += ret;
            }
            else
                parseConstruct( offset + pItem->GetHeaderSize(), pItem );
        }

        if( pItem->GetId() == 0 && pItem->GetLength() == 0 && pItem->GetTag() == 0 )
        {
            length = (pItem->GetOffset() + pItem->GetHeaderSize() - start_offset );
            pParentItem->SetLength(length);
            return length;
        }

        offset = next_offset;
    } while ( 1 );

    return -1;
}

int BerModel::getItem(int offset, BerItem *pItem)
{
    int next_offset = 0;
    int position = 0;
    int length = 0;

    int tag = binBer_.pVal[offset + position];

    pItem->SetId( tag & ~JS_TAG_MASK );
    pItem->SetHeaderByte( binBer_.pVal[offset + position], position );
    pItem->SetIndefinite(0);

    tag &= JS_TAG_MASK;
    position++;

    if( tag == JS_TAG_MASK )
    {
        int value;

        tag = 0;

        do {
            value = binBer_.pVal[offset + position];
            tag = (tag << 7) | (value & 0x7F);
            pItem->SetHeaderByte( value, position );
            position++;
        } while ( value & JS_LEN_XTND && position < 5 && (offset + position + 1) < binBer_.nLen );

        if( position >= 5 ) return -1;
    }

    pItem->SetTag(tag);

    if( (offset + position) > binBer_.nLen ) return -1;

    length = binBer_.pVal[offset + position];
    pItem->SetHeaderByte( binBer_.pVal[offset + position], position );
    position++;

    pItem->SetHeaderSize( position );

    if( length & JS_LEN_XTND )
    {
        int i;

        length &= JS_LEN_MASK;

        if( length > 4 ) return -2;

        pItem->SetHeaderSize( pItem->header_size_ + length );
        pItem->SetLength(0);

        for( i = 0; i < length; i++ )
        {
            int ch = binBer_.pVal[offset + position];
            pItem->SetLength( (pItem->length_ << 8) | ch );
            pItem->SetHeaderByte( binBer_.pVal[offset + position], position );
            position++;
        }

        if( !length ) pItem->SetIndefinite(1);
    }
    else {
        pItem->SetLength(length);
        if( length >  ( 1024 * 1024 * 1024 ) )
        {
            fprintf( stderr, "The message length is longer than 1 GBytes(len : %d)\n", length );
            return -1;
        }
    }

    next_offset = offset + position + pItem->length_;

    return next_offset;
}

#if 0
int getItemA( const BIN *pBer, BerItem *pItem )
{
    int position = 0;
    int length = 0;

    int tag = pBer->pVal[position];

    pItem->SetId( tag & ~JS_TAG_MASK );
    pItem->SetHeaderByte( pBer->pVal[position], position );
    pItem->SetIndefinite(0);

    tag &= JS_TAG_MASK;
    position++;

    if( tag == JS_TAG_MASK )
    {
        int value;

        tag = 0;

        do {
            value = pBer->pVal[position];
            tag = (tag << 7) | (value & 0x7F);
            pItem->SetHeaderByte( value, position );
            position++;
        } while ( value & JS_LEN_XTND && position < 5 && (position + 1) < pBer->nLen );

        if( position >= 5 ) return -1;
    }

    pItem->SetTag(tag);

    if( (position) > pBer->nLen ) return -1;

    length = pBer->pVal[position];
    pItem->SetHeaderByte( pBer->pVal[position], position );
    position++;

    pItem->SetHeaderSize( position );

    if( length & JS_LEN_XTND )
    {
        int i;

        length &= JS_LEN_MASK;

        if( length > 4 ) return -2;

        pItem->SetHeaderSize( pItem->header_size_ + length );
        pItem->SetLength(0);

        for( i = 0; i < length; i++ )
        {
            int ch = pBer->pVal[position];
            pItem->SetLength( (pItem->length_ << 8) | ch );
            pItem->SetHeaderByte( pBer->pVal[position], position );
            position++;
        }

        if( !length ) pItem->SetIndefinite(1);
    }
    else {
        pItem->SetLength(length);
    }

    return 0;
}
#endif

int BerModel::resizeParentHeader( int nDiffLen, const BerItem *pItem, QModelIndexList &indexList )
{
    int nResizeLen = 0;
    if( pItem == NULL ) return -1;

    if( nDiffLen == 0 ) return 0;

    nResizeLen = nDiffLen;

    BerItem *pParent = (BerItem *)pItem->parent();

    while( pParent )
    {
        int nOldLen = 0;
        int nOldHeaderLen = 0;

        BIN binHeader = {0,0};

        indexList.append( pParent->index() );

        nOldLen = pParent->GetLength();
        nOldHeaderLen = pParent->GetHeaderSize();

        pParent->changeLength( nOldLen + nResizeLen, &nResizeLen );
        if( nResizeLen == 0 ) break;

        pParent->getHeaderBin( &binHeader );
        JS_BIN_changeBin( pParent->GetOffset(), nOldHeaderLen, &binHeader, &binBer_ );
        JS_BIN_reset( &binHeader );

        pParent = (BerItem *)pParent->parent();
    }

    return 0;
}
