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

    /*
    JS_BIN_reset( &binBer_ );
    BerItem *root = new BerItem();
    BerItem *sec = new BerItem();
    BerItem *third = new BerItem();

    QStringList labels;
    labels << "BerViewer";
    setHorizontalHeaderLabels( labels );

    root->setText( "aaa" );
    sec->setText( "sec" );
    third->setText( "third" );


    insertRow( 0, root );
    insertRow( 1, sec );

    root->insertRow( 0, third );
    */

//   setItem(0,0, root);
}


int BerModel::openFile( const QString& filePath )
{
    int         nRet = 0;

    BIN         bData;

//    memset( &bData, 0x00, sizeof(BIN));

//    nRet = JS_BIN_fileRead( filePath.toStdString().c_str(), &bData );

    return nRet;
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
    int indefinite = 0;
    BerItem *pRootItem = new BerItem();


    clear();
    QStringList labels;
    labels << "BerViewer";
    setHorizontalHeaderLabels( labels );

    pRootItem->SetOffset(offset);
    pRootItem->SetLevel(0);

    offset = getItem( 0, pRootItem );
    insertRow( 0, pRootItem );

    pRootItem->setText( pRootItem->GetTagString() );

    if( (pRootItem->GetId() & FORM_MASK) == CONSTRUCTED )
        ret = parseBer( pRootItem->GetHeaderSize(), 1, pRootItem->GetIndefinite(), pRootItem );

    return 0;
}

int BerModel::parseBer(int offset, int level, int indefinite, BerItem *pParentItem)
{
    int     ret = 0;
    int     next_offset = 0;
    int     isConstructed = 0;



    do {
        if( offset >= binBer_.nLen ) break;

        BerItem *pItem = new BerItem();
        pItem->SetOffset(offset);
        pItem->SetLevel(level);
        next_offset = getItem( offset, pItem );

        if( next_offset <= 0 ) return -1;
        pItem->setText( pItem->GetTagString() );


        pParentItem->appendRow( pItem );

        if( (pItem->GetId() & FORM_MASK) == CONSTRUCTED )
            isConstructed = 1;
        else {
            isConstructed = 0;
        }

        if( isConstructed )
        {
            parseBer( offset + pItem->GetHeaderSize(), level+1, pItem->GetIndefinite(), pItem );
        }

        if( indefinite )
        {

        }
        else {
                if( next_offset >= binBer_.nLen ) break;
        }

        offset = next_offset;

    } while( next_offset > 0 );

    return 0;
}

int BerModel::getItem(int offset, BerItem *pItem)
{
    int next_offset = 0;
    int position = 0;
    int length = 0;

    int tag = binBer_.pVal[offset + position];

    pItem->SetId( tag & ~TAG_MASK );
    pItem->SetHeaderByte( binBer_.pVal[offset + position], position );
    pItem->SetIndefinite(0);

    tag &= TAG_MASK;
    position++;

    if( tag == TAG_MASK )
    {
        int value;

        tag = 0;

        do {
            value = binBer_.pVal[offset + position];
            tag = (tag << 7) | (value & 0x7F);
            pItem->SetHeaderByte( value, position );
            position++;
        } while ( value & LEN_XTND && position < 5 && (offset + position + 1) < binBer_.nLen );

        if( position >= 5 ) return -1;
    }

    pItem->SetTag(tag);

    if( (offset + position) > binBer_.nLen ) return -1;

    length = binBer_.pVal[offset + position];
    pItem->SetHeaderByte( binBer_.pVal[offset + position], position );
    position++;

    pItem->SetHeaderSize( position );

    if( length & LEN_XTND )
    {
        int i;

        length &= LEN_MASK;

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
    }

    next_offset = offset + position + pItem->length_;

    return next_offset;
}
