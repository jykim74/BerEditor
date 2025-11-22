/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "ber_item.h"
#include "ber_model.h"
#include "js_bin.h"
#include "js_error.h"
#include "ber_applet.h"
#include "common.h"

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


void BerModel::setBER(const BIN *pBer )
{
    JS_BIN_reset( &binBer_ );
    if( pBer != NULL ) JS_BIN_copy( &binBer_, pBer );
}

int BerModel::parseTree( bool bExpand )
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
    if( offset < 0 ) return -1;

    insertRow( 0, pRootItem );

    pRootItem->setText( pRootItem->GetInfoString( &binBer_) );

    if( (pRootItem->GetId() & JS_FORM_MASK) == JS_CONSTRUCTED )
    {
        if( pRootItem->GetIndefinite() )
            ret = parseIndefiniteConstruct( pRootItem->GetHeaderSize(), pRootItem, bExpand );
        else
            ret = parseConstruct( pRootItem->GetHeaderSize(), pRootItem, bExpand );
    }
    else
    {
        if( bExpand == true )
        {
            int start = -1;
            int len = -1;

            if( pRootItem->GetTag() == JS_OCTETSTRING )
            {
                start = pRootItem->GetHeaderSize();
                len = pRootItem->GetLength();
                if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                {
                    ret = parseConstruct( start, pRootItem, bExpand );
                }
            }
            else if( pRootItem->GetTag() == JS_BITSTRING )
            {
                start = pRootItem->GetHeaderSize() + 1;
                len = pRootItem->GetLength() - 1;
                if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                {
                    ret = parseConstruct( start, pRootItem, bExpand );
                }
            }
        }
    }

    return 0;
}

int BerModel::parseConstruct(int offset, BerItem *pParentItem, bool bExpand )
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
                ret = parseIndefiniteConstruct( offset + pItem->GetHeaderSize(), pItem, bExpand );
                if( ret <= 0 ) return -1;
                next_offset += ret;
            }
            else
            {
                if( pItem->length_ > 0 ) parseConstruct( offset + pItem->GetHeaderSize(), pItem, bExpand );

                int end = start_offset + pParentItem->GetLength();
                if( pParentItem->GetTag() == JS_BITSTRING ) end--;

                if( next_offset >= end ) break;
            }
        }
        else
        {
            if( bExpand == true )
            {
                int start = -1;
                int len = -1;

                if( pItem->GetTag() == JS_OCTETSTRING )
                {
                    start = offset + pItem->GetHeaderSize();
                    len = pItem->GetLength();

                    if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                    {
                        ret = parseConstruct( start, pItem, bExpand );
                    }
                }
                else if( pItem->GetTag() == JS_BITSTRING )
                {
                    start = offset + pItem->GetHeaderSize() + 1;
                    len = pItem->GetLength() - 1;

                    if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                    {
                        ret = parseConstruct( start, pItem, bExpand );
                    }
                }
            }
        }

        offset = next_offset;

    } while( next_offset > 0 && next_offset < (start_offset + pParentItem->GetLength()) );

    return 0;
}

int BerModel::parseIndefiniteConstruct( int offset, BerItem *pParentItem, bool bExpand )
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
                ret = parseIndefiniteConstruct( offset + pItem->GetHeaderSize(), pItem, bExpand );
                if( ret <= 0 ) return -1;
                next_offset += ret;
            }
            else
                parseConstruct( offset + pItem->GetHeaderSize(), pItem, bExpand );
        }
        else
        {
            if( bExpand == true )
            {
                int start = -1;
                int len = -1;

                if( pItem->GetTag() == JS_OCTETSTRING )
                {
                    start = offset + pItem->GetHeaderSize();
                    len = pItem->GetLength();

                    if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                    {
                        ret = parseConstruct( start, pItem, bExpand );
                    }
                }
                else if( pItem->GetTag() == JS_BITSTRING )
                {
                    start = offset + pItem->GetHeaderSize() + 1;
                    len = pItem->GetLength() - 1;

                    if( JS_BER_isExpandable( &binBer_.pVal[start], len ) == 1 )
                    {
                        ret = parseConstruct( start, pItem, bExpand );
                    }
                }
            }
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

#if 0
int BerModel::resizeParentHeader( int nDiffLen, const BerItem *pItem, BIN *pBER )
{
    int nResizeLen = 0;
    if( pItem == NULL ) return -1;

#ifdef QT_DEBUG
    berApplet->log( QString( "DiffLen: %1" ).arg( nDiffLen ));
#endif

    if( nDiffLen == 0 ) return 0;

    nResizeLen = nDiffLen;

    BerItem *pParent = (BerItem *)pItem->parent();

#ifdef QT_DEBUG
    if( pParent == NULL ) berApplet->log( "Current is top" );
#endif

    while( pParent )
    {
        int nOldLen = 0;
        int nOldHeaderLen = 0;

        BIN binHeader = {0,0};

#ifdef QT_DEBUG
        BIN binOrgHeader = {0,0};
        int nLevel = pParent->GetLevel();
        pParent->getHeaderBin( &binOrgHeader );
        berApplet->log( "" );
        berApplet->log( QString( "Org Header[%1] : %2" ).arg( nLevel ).arg( getHexString( &binOrgHeader)));
        JS_BIN_reset( &binOrgHeader );
#endif

        nOldLen = pParent->GetLength();
        nOldHeaderLen = pParent->GetHeaderSize();

        pParent->changeLength( nOldLen + nResizeLen, &nResizeLen );

        /* Indefinte 경우가 있어서 항상 끝까지 체크 햬야 함 */
        if( nResizeLen == 0 )
        {
#ifdef QT_DEBUG
            berApplet->log( "The size is the same" );
#endif
            continue;
        }

        pParent->getHeaderBin( &binHeader );

#ifdef QT_DEBUG
        berApplet->log( QString( "New Header[%1] : %2" ).arg( nLevel ).arg( getHexString( &binHeader)));
#endif

        JS_BIN_changeBin( pBER, pParent->GetOffset(), nOldHeaderLen, &binHeader );

        JS_BIN_reset( &binHeader );

        pParent = (BerItem *)pParent->parent();
    }

    return 0;
}
#endif

int BerModel::resizeItemHead( BIN *pBER, BerItem *pItem, int nModItemLen )
{
    int ret = 0;
    int nOrgLen = 0;
    int nOrgHeadLen = 0;
    BIN binNewHead = {0,0};
    int nDiffLen = 0;
    int nNewLen = 0;

    if( pBER == NULL || pItem == NULL ) return JSR_ERR;

    nOrgLen = pItem->GetLength();
    nOrgHeadLen = pItem->GetHeaderSize();

    if( nModItemLen == 0 )
        return 0;

    nNewLen = nOrgLen;
    nNewLen += nModItemLen;

    if( pItem->GetIndefinite() == true )
    {
        pItem->SetLength( nNewLen );
        return 0;
    }

#ifdef QT_DEBUG
    BIN binOrgHead = {0,0};
    int nLevel = pItem->GetLevel();
    pItem->getHeaderBin( &binOrgHead );
    berApplet->log( "" );
    berApplet->log( QString( "Org Header[%1] : %2" ).arg( nLevel ).arg( getHexString( &binOrgHead)));
    JS_BIN_reset( &binOrgHead );
#endif

    ret = pItem->changeLength( nNewLen, &nDiffLen );
    if( ret != JSR_OK ) goto end;

    pItem->getHeaderBin( &binNewHead );

#ifdef QT_DEBUG
    berApplet->log( QString( "New Header[%1] : %2" ).arg( nLevel ).arg( getHexString( &binNewHead)));
#endif

    ret = JS_BIN_changeBin( pBER, pItem->GetOffset(), nOrgLen, &binNewHead );

end :
    JS_BIN_reset( &binNewHead );
    return ret;
}

int BerModel::resizeHeadToTop( BIN *pBER, BerItem *pItem, int nModItemLen )
{
    int ret = 0;
    BerItem *pParent = NULL;
    int nOrgLen = 0;
    int nNewLen = 0;
    int nModLen = 0;

    nOrgLen = pItem->GetItemSize();
    ret = resizeItemHead( pBER, pItem, nModItemLen );
    if( ret != 0 ) return ret;
    nNewLen = pItem->GetItemSize();

    pParent = pItem;
    nModLen = nNewLen - nOrgLen;

    while( pParent )
    {
        nOrgLen = pParent->GetItemSize();
        ret = resizeItemHead( pBER, pParent, nModLen );
        if( ret != 0 ) break;

        nNewLen = pParent->GetItemSize();
        nModLen = nNewLen - nOrgLen;

        pParent = (BerItem *)pParent->parent();
    }

    return ret;
}

int BerModel::addItem( BerItem* pParentItem, const BIN *pData )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    int nOrgLen = 0;
    int nOrgHeaderLen = 0;
    int nDiffLen = 0;

    if( pParentItem == NULL ) return -1;

    JS_BIN_copy( &binMod, &binBer_ );

    if( pParentItem->GetIndefinite() == true )
    {
        int nPos = pParentItem->GetOffset() + pParentItem->GetHeaderSize() + pParentItem->GetValLength();
        ret = JS_BIN_insertBin( &binMod, nPos, pData );
        if( ret != 0 ) goto end;
    }
    else
    {
        nOrgLen = pParentItem->GetLength();
        nOrgHeaderLen = pParentItem->GetHeaderSize();

        JS_BIN_insertBin( &binMod, pParentItem->GetOffset() + nOrgHeaderLen + nOrgLen, pData );

        ret = pParentItem->changeLength( nOrgLen + pData->nLen, &nDiffLen );

        if( nDiffLen <= 0 || ret != 0 )
        {
            ret = JSR_ERR;
            goto end;
        }

        pParentItem->getHeaderBin( &binHeader );
        JS_BIN_changeBin( &binMod, pParentItem->GetOffset(), nOrgHeaderLen, &binHeader );
    }

//    ret = resizeParentHeader( nDiffLen, pParentItem, &binMod );
    ret = resizeHeadToTop( &binMod, pParentItem, pData->nLen );
    if( ret != 0 ) goto end;
    setBER( &binMod );

end :
    // 실패시 원래대로 길이를 원복함
    if( ret != 0 ) pParentItem->changeLength( nOrgLen, &nDiffLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );

    return ret;
}

int BerModel::removeItem( BerItem *pItem )
{
    int ret = 0;
    int nDiffLen = 0;
    BIN binMod = {0,0};
    BerItem *pParent = NULL;


    if( pItem == NULL ) return -1;

    JS_BIN_copy( &binMod, &binBer_ );

    nDiffLen = pItem->GetItemSize();

    ret = JS_BIN_removeBin( &binMod, pItem->GetOffset(), nDiffLen );
    if( ret != 0 ) goto end;

    pParent = (BerItem *)pItem->parent();
    ret = resizeHeadToTop( &binMod, pParent, -1 );

//    ret = resizeParentHeader( -nDiffLen, pItem, &binMod );
    if( ret != 0 ) goto end;

    setBER( &binMod );

end :
    JS_BIN_reset( &binMod );
    return ret;
}

int BerModel::modifyItem( BerItem *pItem, const BIN *pValue )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    BIN binChange = {0,0};

    int nDiffLen = 0;
    int nOrgLen = 0;
    int nNewLen = 0;
    int nModLen = 0;

    if( pItem == NULL ) return -1;
    JS_BIN_copy( &binMod, &binBer_ );

    nOrgLen = pItem->GetItemSize();

    ret = pItem->changeLength( pValue->nLen, &nDiffLen );
    if( ret != 0 )
    {
        ret = JSR_ERR;
        goto end;
    }

    nNewLen = pItem->GetItemSize();
    nModLen = nNewLen - nOrgLen;

    pItem->getHeaderBin( &binHeader );
    JS_BIN_copy( &binChange, &binHeader );
    JS_BIN_appendBin( &binChange, pValue );

    ret = JS_BIN_changeBin( &binMod, pItem->GetOffset(), nOrgLen, &binChange );
    if( ret != 0 ) goto end;

    ret = resizeHeadToTop( &binMod, pItem, nModLen );
    if( ret != 0 ) goto end;

    setBER( &binMod );

end :
    if( ret != 0 ) pItem->changeLength( nOrgLen, &nDiffLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binChange );

    return ret;
}
