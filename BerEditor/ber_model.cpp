/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QElapsedTimer>

#include "ber_item.h"
#include "ber_model.h"
#include "js_bin.h"
#include "js_error.h"
#include "ber_applet.h"
#include "common.h"
#include "js_pki.h"
#include "mainwindow.h"
#include "ber_tree_view.h"

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

void BerModel::getTablePosition( int nOffset, int *pRow, int *pCol )
{
    if( nOffset < 0 ) return;

    int nRow = int( nOffset / 16 );
    int nCol = ( nOffset % 16) + 1;

    *pRow = nRow;
    *pCol = nCol;
}

int BerModel::getItemInfo( const BIN *pBER, int nOffset, BerItem *pItem )
{
    int nPosition = 0;
    int nTag = 0;
    int nLength = 0;

    if( pBER == NULL || pItem == NULL || nOffset < 0 )
        return JSR_BAD_ARG;

    if( nOffset > (pBER->nLen - 2) )
        return JSR_BER_BAD_OFFSET;

    nTag = pBER->pVal[nOffset + nPosition];

    pItem->SetOffset( nOffset );
    pItem->SetHeaderByte( pBER->pVal[nOffset + nPosition], nPosition );

    nTag &= JS_TAG_MASK;
    nPosition++;

    if( nTag == JS_TAG_MASK )
    {
        int nValue = 0;
        /* Long tag encoded as sequence of 7-bit values.  This doesn't try to
           handle tags > INT_MAX, it'd be pretty peculiar ASN.1 if it had to
           use tags this large */

        do {
            nValue = pBER->pVal[nOffset + nPosition];
            nTag = ( nTag << 7) | ( nValue & 0x7F );
            pItem->SetHeaderByte( nValue, nPosition );
            nPosition++;
        } while( nValue & JS_LEN_XTND && nPosition < 5 );

        if( nPosition >= 5 ) return JSR_BER_BAD_HEADER;
    }

    if( ( nOffset + nPosition ) > pBER->nLen ) return JSR_BER_BAD_OFFSET;

    nLength = pBER->pVal[nOffset + nPosition];
    pItem->SetHeaderByte( pBER->pVal[nOffset + nPosition], nPosition );
    nPosition++;


    if( nLength & JS_LEN_XTND )
    {
        nLength &= JS_LEN_MASK;
        if( nLength > 4 ) return JSR_BER_BAD_LENGTH;

        pItem->SetLength(0);

        if( nLength == 0x00 )
        {
            pItem->SetHeaderSize( nPosition );
            pItem->SetIndefinite( true );
        }
        else
        {
            pItem->SetIndefinite( false );

            for( int i = 0; i < nLength; i++ )
            {
                int nCh = pBER->pVal[nOffset + nPosition];
                pItem->SetLength( (pItem->length_ << 8) | nCh );
                pItem->SetHeaderByte( pBER->pVal[nOffset + nPosition], nPosition );
                nPosition++;
            }

            pItem->SetHeaderSize( nPosition );
            if( pItem->GetLength() > JS_BER_MAX_SIZE )
                return JSR_BER_OVER_MAXSIZE;
        }
    }
    else
    {
        pItem->SetHeaderSize( nPosition );
        pItem->SetIndefinite( false );
        pItem->SetLength( nLength );
    }

    pItem->setText( pItem->GetInfoString( pBER ));

    return JSR_OK;
}

int BerModel::getItemInfo( int nOffset, BerItem *pItem )
{
    return getItemInfo( &binBer_, nOffset, pItem );
}

int BerModel::getConstructedItemInfo( const BIN *pBER, int nStart, BerItem *pItem, bool bExpand )
{
    int nRet = 0;

    int nOffset = 0;
    int nLevel = 0;
    bool bConstructed = false;

    if( pBER == NULL || pItem == NULL ) return JSR_BAD_ARG;

    if( nStart >= pBER->nLen ) return JSR_BER_BAD_OFFSET;

    nLevel = pItem->GetLevel() + 1;
    nOffset = nStart;

    do {
        BerItem *pChild = new BerItem;
        pChild->SetOffset( nOffset );
        pChild->SetLevel( nLevel );

        nRet = getItemInfo( pBER, nOffset, pChild );
        if( nRet != 0 )
        {
            berApplet->elog( QString("failed to get item information: %1").arg(JERR(nRet)));
            break;
        }

        pItem->appendRow( pChild );

        if( pChild->isConstructed() == true )
            bConstructed = true;
        else
            bConstructed = false;

        if( bConstructed == true )
        {
            nRet = getConstructedItemInfo( pBER, nOffset + pChild->GetHeaderSize(), pChild, bExpand );
            if( nRet != JSR_OK ) return nRet;
        }
        else
        {
            if( bExpand == true )
            {
                if( pChild->isType( JS_OCTETSTRING ) || pChild->isType( JS_BITSTRING ) )
                {
                    int nChildStart = -1;
                    int nChildLen = -1;

                    if( pChild->isType( JS_OCTETSTRING ) )
                    {
                        nChildStart = nOffset + pChild->GetHeaderSize();
                        nChildLen = pChild->GetLength();
                    }
                    else
                    {
                        nChildStart = nOffset + pChild->GetHeaderSize() + 1;
                        nChildLen = pChild->GetLength() - 1;
                    }

                    if( JS_BER_isExpandable( &binBer_.pVal[nChildStart], nChildLen ) == 1 )
                    {
                        nRet = getConstructedItemInfo( pBER, nChildStart, pChild, bExpand );
                    }
                }
            }
        }

        nOffset += pChild->GetItemSize();

        if( pItem->GetIndefinite() == false )
        {
            int nEnd = nStart + pItem->GetLength();

            // BITSTRING 경우는 Unused 표시 바이트 다음 부터여서 길이에서 1을 빼주어야 함
            if( pItem->isType( JS_BITSTRING ) )
                nEnd = nEnd - 1;

            if( nOffset >= nEnd )
                return JSR_OK;
        }
        else
        {
            if( pChild->isEOC() == true )
            {
                int nLen = nOffset - nStart;
                pItem->SetLength( nLen );
                return JSR_OK;
            }
        }

        if( nOffset >= (pBER->nLen - 1) ) return JSR_BER_BAD_OFFSET;

    } while( 1 );

    return nRet;
}

int BerModel::makeTree( bool bExpand )
{
    int ret = 0;
    int offset = 0;

    BerItem *pRootItem = new BerItem();

    clear();
    QStringList labels;
    setHorizontalHeaderLabels( labels );

    pRootItem->SetOffset(offset);
    pRootItem->SetLevel(0);

    ret = getItemInfo( &binBer_, 0, pRootItem );
    if( ret < 0 ) return ret;

    insertRow( 0, pRootItem );
    if( pRootItem->isConstructed() == true )
    {
        ret = getConstructedItemInfo( &binBer_, pRootItem->GetHeaderSize(), pRootItem, bExpand );
        if( ret != JSR_OK ) return ret;
    }

    if( bExpand == true )
    {
        if( pRootItem->isType( JS_OCTETSTRING ) || pRootItem->isType( JS_BITSTRING ) )
        {
            int nChildStart = -1;
            int nChildLen = -1;

            if( pRootItem->isType( JS_OCTETSTRING ) )
            {
                nChildStart = pRootItem->GetHeaderSize();
                nChildLen = pRootItem->GetLength();
            }
            else
            {
                nChildStart = pRootItem->GetHeaderSize() + 1;
                nChildLen = pRootItem->GetLength() - 1;
            }

            if( JS_BER_isExpandable( &binBer_.pVal[nChildStart], nChildLen ) == 1 )
            {
                ret = getConstructedItemInfo( &binBer_, nChildStart, pRootItem, bExpand );
                if( ret != JSR_OK ) return ret;
            }
        }
    }

    return ret;
}

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

    ret = JS_BIN_changeBin( pBER, pItem->GetOffset(), nOrgHeadLen, &binNewHead );

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

    pParent = (BerItem *)pItem->parent();
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

const BerItem* BerModel::addItem( BerItem* pParentItem, bool bFirst, const BIN *pData )
{
    int ret = 0;
    BIN binMod = {0,0};
    int nPos = 0;
    BerItem *pNewItem = nullptr;

    if( pParentItem == NULL ) return nullptr;

    JS_BIN_copy( &binMod, &binBer_ );

    if( bFirst == true )
    {
        nPos = pParentItem->GetOffset() + pParentItem->GetHeaderSize();
        ret = JS_BIN_insertBin( &binMod, nPos, pData );
        if( ret != 0 ) goto end;
    }
    else
    {
        if( pParentItem->GetIndefinite() == true )
        {
            nPos = pParentItem->GetOffset() + pParentItem->GetHeaderSize() + pParentItem->GetValLength();
            ret = JS_BIN_insertBin( &binMod, nPos, pData );
            if( ret != 0 ) goto end;
        }
        else
        {
            nPos = pParentItem->GetOffset() + pParentItem->GetItemSize();

            ret = JS_BIN_insertBin( &binMod, nPos, pData );
            if( ret != 0 ) goto end;
        }
    }

    resizeHeadToTop( &binMod, pParentItem, pData->nLen );
    setBER( &binMod );
    pNewItem = new BerItem;

    getItemInfo( nPos, pNewItem );
    pNewItem->SetLevel( pParentItem->GetLevel() + 1 );

    if( bFirst == true )
        pParentItem->insertRow( 0, pNewItem );
    else
        pParentItem->appendRow( pNewItem );

end :
    JS_BIN_reset( &binMod );
    return pNewItem;
}

int BerModel::removeItem( BerItem *pItem )
{
    int ret = 0;
    int nDiffLen = 0;
    BIN binMod = {0,0};
    BerItem *pParent = NULL;

    if( pItem == NULL ) return JSR_ERR;

    if( pItem->parent() == NULL ) JSR_ERR2;

    JS_BIN_copy( &binMod, &binBer_ );

    nDiffLen = pItem->GetItemSize();

    ret = JS_BIN_removeBin( &binMod, pItem->GetOffset(), nDiffLen );
    if( ret != 0 ) goto end;

    pParent = (BerItem *)pItem->parent();
    if( pParent ) resizeHeadToTop( &binMod, pParent, -nDiffLen );

    setBER( &binMod );

    if( pParent )
    {
        int count = pParent->rowCount();
        for( int i = 0; i < count; i++ )
        {
            BerItem *curItem = (BerItem *)pParent->child( i );
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

int BerModel::modifyItem( BerItem *pItem, const BIN *pValue )
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binHeader = {0,0};
    BIN binChange = {0,0};

    int nDiffLen = 0;
    int nOrgLen = 0;

    BerItem *pParent = NULL;

    if( pItem == NULL ) return -1;
    JS_BIN_copy( &binMod, &binBer_ );

    nOrgLen = pItem->GetItemSize();

    ret = pItem->changeLength( pValue->nLen, &nDiffLen );
    if( ret != 0 )
    {
        ret = JSR_ERR;
        goto end;
    }

    pItem->getHeaderBin( &binHeader );
    JS_BIN_copy( &binChange, &binHeader );
    JS_BIN_appendBin( &binChange, pValue );

    ret = JS_BIN_changeBin( &binMod, pItem->GetOffset(), nOrgLen, &binChange );
    if( ret != 0 ) goto end;

    pParent = (BerItem *)pItem->parent();
    if( pParent )
    {
        int nModLen = binChange.nLen - nOrgLen;
        resizeHeadToTop( &binMod, pParent, nModLen );
    }

    setBER( &binMod );
end :
    if( ret != 0 ) pItem->changeLength( nOrgLen, &nDiffLen );

    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binChange );

    return ret;
}

const BerItem* BerModel::findItemByOffset( BerItem* pParentItem, int nOffset )
{
    BerItem *pStartItem = NULL;
    const BerItem *pFoundItem = NULL;
    if( pParentItem == nullptr )
    {
        QModelIndex idx = index(0,0);
        pStartItem = (BerItem *)itemFromIndex( idx );
    }
    else
    {
        pStartItem = pParentItem;
    }

    if( pStartItem == NULL ) return nullptr;

    if( pStartItem->GetOffset() == nOffset ) return pStartItem;

    if( pStartItem->GetOffset() > nOffset ) return nullptr;

    if( pStartItem->hasChildren() == true )
    {
        int nCount = pStartItem->rowCount();

        for( int i = 0; i < nCount; i++ )
        {
            BerItem *pChild = (BerItem *)pStartItem->child( i );
            if( pChild->GetOffset() > nOffset ) break;

            pFoundItem = findItemByOffset( pChild, nOffset );
            if( pFoundItem != nullptr ) return pFoundItem;
        }
    }

    return nullptr;
}

const BerItem* BerModel::findNextItemByValue( const BerItem* pItem, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BerTreeView viewTree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (BerItem *)item(0,0);
    }
    else
    {
        pCurItem = viewTree.getNext( (BerItem *)pItem );
    }

    if( pValue == NULL || pValue->nLen <= 0 ) return pCurItem;

    while( pCurItem )
    {
        if( pCurItem->isConstructed() == false )
        {
            if( pCurItem->isType( JS_BITSTRING ))
            {
                binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize() + 1;
                binCurValue.nLen = pCurItem->GetValLength() - 1;
            }
            else
            {
                binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize();
                binCurValue.nLen = pCurItem->GetValLength();
            }

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

const BerItem* BerModel::findPrevItemByValue( const BerItem* pItem, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BerTreeView viewTree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (BerItem *)item(0,0);
    }
    else
    {
        pCurItem = viewTree.getPrev( (BerItem *)pItem );
    }

    if( pValue == NULL || pValue->nLen <= 0 ) return pCurItem;

    while( pCurItem )
    {
        if( pCurItem->isConstructed() == false )
        {
            if( pCurItem->isType( JS_BITSTRING ))
            {
                binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize() + 1;
                binCurValue.nLen = pCurItem->GetValLength() - 1;
            }
            else
            {
                binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize();
                binCurValue.nLen = pCurItem->GetValLength();
            }

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


const BerItem* BerModel::findNextItemByValue( const BerItem* pItem, BYTE cTag, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BerTreeView viewTree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (BerItem *)item(0,0);
    }
    else
    {
        pCurItem = viewTree.getNext( (BerItem *)pItem );
    }

    while( pCurItem )
    {
        if( cTag == pCurItem->GetTag() )
        {
            if( pValue == NULL || pValue->nLen == 0 ) return pCurItem;

            if( pCurItem->isConstructed() == false )
            {
                if( pCurItem->isType( JS_BITSTRING ))
                {
                    binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize() + 1;
                    binCurValue.nLen = pCurItem->GetValLength() - 1;
                }
                else
                {
                    binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize();
                    binCurValue.nLen = pCurItem->GetValLength();
                }

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

        pCurItem = viewTree.getNext( pCurItem );
    }

    return nullptr;
}

const BerItem* BerModel::findPrevItemByValue( const BerItem* pItem, BYTE cTag, const BIN *pValue, bool bMatched )
{
    int ret = 0;
    BIN binCurValue = {0,0};
    BerTreeView viewTree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = NULL;
    QModelIndex ri;

    if( pValue == NULL )
        return nullptr;

    if( pItem == NULL )
    {
        pCurItem = (BerItem *)item(0,0);
    }
    else
    {
        pCurItem = viewTree.getPrev( (BerItem *)pItem );
    }

    while( pCurItem )
    {
        if( cTag == pCurItem->GetTag() )
        {
            if( pValue == NULL || pValue->nLen == 0 ) return pCurItem;

            if( pCurItem->isConstructed() == false )
            {
                if( pCurItem->isType( JS_BITSTRING ))
                {
                    binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize() + 1;
                    binCurValue.nLen = pCurItem->GetValLength() - 1;
                }
                else
                {
                    binCurValue.pVal = binBer_.pVal + pCurItem->GetOffset() + pCurItem->GetHeaderSize();
                    binCurValue.nLen = pCurItem->GetValLength();
                }

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

        pCurItem = pCurItem = viewTree.getPrev( pCurItem );
    }

    return nullptr;
}


void BerModel::selectValue( BerItem *pItem, const BIN *pValue, bool bPart )
{
    int nStart = 0;
    int nLen = 0;
    if( pItem == NULL) return;

    if( pValue == NULL || pValue->nLen <= 0 ) return;

    BIN binCurValue;
    binCurValue.pVal = binBer_.pVal + pItem->GetOffset() + pItem->GetHeaderSize();
    binCurValue.nLen = pItem->GetValLength();

    int ret = JS_BIN_memmem( &binCurValue, pValue );
    if( ret < 0 ) return;

    if( bPart == true )
        nStart = pItem->GetHeaderSize() + ret;
    else
        nStart = pItem->GetOffset() + pItem->GetHeaderSize() + ret;

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
