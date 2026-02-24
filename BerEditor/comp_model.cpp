#include <QTreeView>
#include <QHeaderView>

#include "comp_model.h"
#include "js_ber.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "ber_compare_dlg.h"
#include "ber_item.h"

CompModel::CompModel(QObject *parent)
{
    setParent( parent );
    memset( &binBER_, 0x00, sizeof(BIN));

    tree_view_ = new CompTree;
    tree_view_->setModel( this );

    tree_view_->header()->setVisible( false );
}

CompModel::~CompModel()
{
    if( tree_view_ ) delete tree_view_;
    JS_BIN_reset( &binBER_ );
}

void CompModel::setBER( const BIN *pBER )
{
    clearView();
    JS_BIN_reset( &binBER_ );
    JS_BIN_copy( &binBER_, pBER );
}

int CompModel::getItemInfo( const BIN *pBER, int nOffset, BerItem *pItem )
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

int CompModel::getItemInfo( int nOffset, BerItem *pItem )
{
    return getItemInfo( &binBER_, nOffset, pItem );
}

int CompModel::getConstructedItemInfo( const BIN *pBER, BerItem *pItem, bool bExpand )
{
    int nRet = 0;

    int nOffset = 0;
    int nLevel = 0;
    bool bConstructed = false;
    int nStart = pItem->GetOffset() + pItem->GetHeaderSize();

    if( pBER == NULL || pItem == NULL ) return JSR_BAD_ARG;

    if( nStart >= pBER->nLen ) return JSR_BER_BAD_OFFSET;

    nLevel = pItem->GetLevel() + 1;
    nOffset = nStart;

    // BIT String Unused Bits 값 스킵
    if( pItem->isType( JS_BITSTRING ) == true ) nOffset++;

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
            nRet = getConstructedItemInfo( pBER, pChild, bExpand );
            if( nRet != JSR_OK ) return nRet;
        }
        else
        {
            if( bExpand == true )
            {
                if( pChild->isType( JS_OCTETSTRING ) || pChild->isType( JS_BITSTRING ) )
                {
                    int nChildStart = pChild->GetOffset() + pChild->GetHeaderSize();
                    int nChildLen = pChild->GetLength();;

                    if( pChild->isType( JS_BITSTRING ) )
                    {
                        nChildStart++;
                        nChildLen--;
                    }

                    if( JS_BER_isExpandable( &binBER_.pVal[nChildStart], nChildLen ) == 1 )
                    {
                        nRet = getConstructedItemInfo( pBER, pChild, bExpand );
                    }
                }
            }
        }

        nOffset += pChild->GetItemSize();

        if( pItem->GetIndefinite() == false )
        {
            int nEnd = nStart + pItem->GetLength();

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

int CompModel::makeTree( bool bExpand )
{
    int ret = 0;
    int offset = 0;

    BerItem *pRootItem = new BerItem();

    clear();
    QStringList labels;
    setHorizontalHeaderLabels( labels );

    pRootItem->SetOffset(offset);
    pRootItem->SetLevel(0);

    ret = getItemInfo( &binBER_, 0, pRootItem );
    if( ret < 0 ) return ret;

    insertRow( 0, pRootItem );
    if( pRootItem->isConstructed() == true )
    {
        ret = getConstructedItemInfo( &binBER_, pRootItem, bExpand );
        if( ret != JSR_OK ) return ret;
    }

    if( bExpand == true )
    {
        if( pRootItem->isType( JS_OCTETSTRING ) || pRootItem->isType( JS_BITSTRING ) )
        {
            int nChildStart = pRootItem->GetHeaderSize();
            int nChildLen = pRootItem->GetLength();

            if( pRootItem->isType( JS_BITSTRING ) )
            {
                nChildStart++;
                nChildLen--;
            }

            if( JS_BER_isExpandable( &binBER_.pVal[nChildStart], nChildLen ) == 1 )
            {
                ret = getConstructedItemInfo( &binBER_, pRootItem, bExpand );
                if( ret != JSR_OK ) return ret;
            }
        }
    }

    tree_view_->expandAll();
    return ret;
}

BerItem* CompModel::getCurrentItem()
{
    QModelIndex idx = tree_view_->currentIndex();
    return (BerItem *)itemFromIndex( idx );
}

void CompModel::getCurrentValue( BIN *pValue )
{
    BerItem* item = getCurrentItem();

    if( item == nullptr ) return;

    item->getValueBin( &binBER_, pValue );
}

void CompModel::getValue( BerItem *item, BIN *pValue )
{
    if( item == nullptr ) return;

    item->getValueBin( &binBER_, pValue );
}

void CompModel::setSelectItem( const BerItem *pItem )
{
    if( pItem == nullptr ) return;

    QModelIndex idx = pItem->index();
    tree_view_->setCurrentIndex( idx );
}

void CompModel::clearSelection()
{
    tree_view_->clearSelection();
}

int CompModel::IsPrev( BerItem *pA, BerItem *pB )
{
    int ret = 0;

    BIN binA = {0,0};
    BIN binB = {0,0};

    if( pA == NULL )
        return 0;

    if( pB == NULL )
        return 1;

    int nLen = 0;
    int nLeft = 0;

    if( pA->GetItemSize() > pB->GetItemSize() )
    {
        nLen = pB->GetItemSize();
    }
    else
    {
        nLen = pA->GetItemSize();
    }

    JS_BIN_set( &binA, pA->header_, pA->header_size_ );
    JS_BIN_set( &binB, pB->header_, pB->header_size_ );

    if( binA.nLen < nLen )
    {
        nLeft = nLen - binA.nLen;
        JS_BIN_append( &binA, &binBER_.pVal[pA->offset_ + pA->header_size_], nLeft );
    }

    if( binB.nLen < nLen )
    {
        nLeft = nLen - binB.nLen;
        JS_BIN_append( &binB, &binBER_.pVal[pB->offset_ + pB->header_size_], nLeft );
    }

    if( memcmp( binA.pVal, binB.pVal, nLen ) > 0 )
        ret = 1;
    else
        ret = 0;

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );

    return ret;
}

const QStringList CompModel::getPositon( BerItem *pItem )
{
    QStringList listPos;

    const BerItem *pCurrent = nullptr;
    pCurrent = pItem;

    while( pCurrent )
    {
        listPos.insert(0, QString("%1").arg( pCurrent->row() ) );

        pCurrent = (BerItem *)pCurrent->parent();
    }

    return listPos;
}

QList<BerItem *> CompModel::getParentList( BerItem *pItem )
{
    QList<BerItem *> listParent;

    const BerItem *pCurrent = nullptr;
    pCurrent = pItem;

    while( pCurrent )
    {
        listParent.insert( 0, (BerItem *)pCurrent );

        pCurrent = (BerItem *)pCurrent->parent();
    }

    return listParent;
}

BerItem* CompModel::findItemByPostion( const QStringList listPos )
{
    BerItem* item = nullptr;
    QModelIndex ri = index(0,0);
    BerItem* root = (BerItem *)itemFromIndex( ri );

    if( root == nullptr ) return nullptr;

    if( listPos.at(0) != "0" )
        return nullptr;

//    if( root->hasChildren() == false )
//        return nullptr;

    item = root;

    for( int i = 0; i < listPos.size(); i++ )
    {
        QString strPos = listPos.at(i);

        if( item->row() != strPos.toInt() )
            return nullptr;

        if( i < ( listPos.size() - 1 ) )
        {
            QString strNext = listPos.at( i + 1 );
            if( item->hasChildren() == false )
                return nullptr;

            item = (BerItem *)item->child( strNext.toInt(), 0 );
            if( item == nullptr ) return nullptr;
        }
    }

    return item;
}

BerItem* CompModel::getNext( BerItem *pItem )
{
    if( tree_view_ == nullptr ) return nullptr;

    return tree_view_->getNext( pItem );
}

BerItem* CompModel::getPrev( BerItem *pItem )
{
    if( tree_view_ == nullptr ) return nullptr;

    return tree_view_->getNext( pItem );
}

void CompModel::setItemColor( BerItem *pItem, QColor cr )
{
    if( tree_view_ == nullptr ) return;

    tree_view_->setItemColor( pItem, cr );
}

void CompModel::setAllColor( QColor cr )
{
    BerItem* item = getNext( NULL );

    while( item )
    {
        setItemColor( item, cr );
        item = getNext( item );
    }
}

void CompModel::clearView()
{
    if( tree_view_ == nullptr ) return;

    clear();
}
