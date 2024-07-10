#include "js_bin.h"
#include "kmip.h"
#include "js_kms.h"
#include "ttlv_tree_item.h"



TTLVTreeItem::TTLVTreeItem()
{
    offset_ = -1;
    level_ = -1;

    memset( &header_, 0x00, sizeof(BIN));
    setEditable(false);
}

TTLVTreeItem::~TTLVTreeItem()
{
    JS_BIN_reset( &header_ );
}

void TTLVTreeItem::setHeader( const unsigned char *pValue, int nLength )
{
    JS_BIN_reset( &header_ );
    JS_BIN_set( &header_, pValue, nLength );
}

void TTLVTreeItem::setOffset( int offset )
{
    offset_ = offset;
}

void TTLVTreeItem::setLevel( int level )
{
    level_ = level;
}

int TTLVTreeItem::getHeader( BIN *pHeader )
{
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    JS_BIN_copy( pHeader, &header_ );
    return 0;
}

int TTLVTreeItem::getTag( BIN *pTag )
{
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    JS_BIN_set( pTag, &header_.pVal[JS_TTLV_TAG_OFFSET], JS_TTLV_TAG_SIZE );

    return 0;
}

int TTLVTreeItem::getType( BIN *pType )
{
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    JS_BIN_set( pType, &header_.pVal[JS_TTLV_TYPE_OFFSET], JS_TTLV_TYPE_SIZE );

    return 0;
}

int TTLVTreeItem::getLength( BIN *pLength )
{
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    JS_BIN_set( pLength, &header_.pVal[JS_TTLV_LENGTH_OFFSET], JS_TTLV_LENGTH_SIZE );

    return 0;
}

int TTLVTreeItem::getValue( const BIN *pTTLV, BIN *pValue )
{
    if( header_.nLen != JS_TTLV_HEADER_SIZE || offset_ < 0) return -1;

    JS_BIN_set( pValue, &pTTLV->pVal[offset_ + JS_TTLV_HEADER_SIZE], getLengthInt() );

    return 0;
}

QString TTLVTreeItem::getTagHex()
{
    char *pHex = NULL;
    BIN binTag = {0,0};

    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binTag.pVal = &header_.pVal[JS_TTLV_TAG_OFFSET];
    binTag.nLen = JS_TTLV_TAG_SIZE;

    JS_BIN_encodeHex( &binTag, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

QString TTLVTreeItem::getTypeHex()
{
    char *pHex = NULL;
    BIN binType = {0,0};
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binType.pVal = &header_.pVal[JS_TTLV_TYPE_OFFSET];
    binType.nLen = JS_TTLV_TYPE_SIZE;

    JS_BIN_encodeHex( &binType, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

int TTLVTreeItem::getType()
{
    int nType = -1;
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    return header_.pVal[JS_TTLV_TYPE_OFFSET];
}

QString TTLVTreeItem::getLengthHex()
{
    char    *pHex = NULL;
    BIN binLen = {0,0};
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binLen.pVal = &header_.pVal[JS_TTLV_LENGTH_OFFSET];
    binLen.nLen = JS_TTLV_LENGTH_SIZE;

    JS_BIN_encodeHex( &binLen, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

QString TTLVTreeItem::getValueHex( const BIN *pTTLV )
{
    char *pHex = NULL;

    BIN binVal = {0,0};

    if( header_.nLen != JS_TTLV_HEADER_SIZE || offset_ < 0 ) return "";

    binVal.pVal = &pTTLV->pVal[offset_ + JS_TTLV_HEADER_SIZE];
    binVal.nLen = getLengthInt();

    JS_BIN_encodeHex( &binVal, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

int32 TTLVTreeItem::getLengthInt()
{
    int32   len = 0;
    BIN binLen = {0,0};

    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return -1;

    binLen.pVal = &header_.pVal[JS_TTLV_LENGTH_OFFSET];
    binLen.nLen = JS_TTLV_LENGTH_SIZE;

    len = JS_BIN_int( &binLen );

    return len;
}

QString TTLVTreeItem::getTagName()
{
    int nTag = -1;
    QString strName;
    BIN binTag = {0,0};

    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binTag.pVal = &header_.pVal[JS_TTLV_TAG_OFFSET];
    binTag.nLen = JS_TTLV_TAG_SIZE;
    nTag = JS_BIN_int( &binTag );

    strName = JS_KMS_tagName( nTag );

    return strName;
}

QString TTLVTreeItem::getTypeName()
{
    int nType = -1;
    QString strName;
    BIN binType = {0,0};
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binType.pVal = &header_.pVal[JS_TTLV_TYPE_OFFSET];
    binType.nLen = JS_TTLV_TYPE_SIZE;

    nType = JS_BIN_int( &binType );

    strName = JS_KMS_typeName( nType );

    return strName;
}

QString TTLVTreeItem::getTitle( const BIN *pTTLV )
{
    QString strTitle;
    QString strTag = getTagName();
    QString strType = getTypeName();

    BIN binType = {0,0};
    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binType.pVal = &header_.pVal[JS_TTLV_TYPE_OFFSET];
    binType.nLen = JS_TTLV_TYPE_SIZE;

    int nType = JS_BIN_int( &binType );

    if( nType == KMIP_TYPE_INTEGER ||
            nType == KMIP_TYPE_TEXT_STRING ||
            nType == KMIP_TYPE_ENUMERATION )
    {
        QString strPrint = getPrintValue( pTTLV );
        strTitle = QString( "%1(%2 %3)").arg( strTag ).arg(strType).arg(strPrint);
    }
    else
    {
        strTitle = QString( "%1(%2)").arg( strTag ).arg(strType);
    }

    return strTitle;
}

QString TTLVTreeItem::getPrintValue( const BIN *pTTLV )
{
    BIN binType = {0,0};
    BIN binVal = {0,0};

    if( header_.nLen != JS_TTLV_HEADER_SIZE ) return "";

    binType.pVal = &header_.pVal[JS_TTLV_TYPE_OFFSET];
    binType.nLen = JS_TTLV_TYPE_SIZE;

    binVal.pVal = &pTTLV->pVal[offset_ + JS_TTLV_HEADER_SIZE];
    binVal.nLen = getLengthInt();

    int nType = JS_BIN_int( &binType );
    QString strPrint;

    if( nType == KMIP_TYPE_INTEGER )
    {
        int num = JS_BIN_int( &binVal );
        strPrint = QString( "%1" ).arg( num );
    }
    else if( nType == KMIP_TYPE_TEXT_STRING )
    {
        char *pTmp = (char *)JS_malloc( binVal.nLen + 1 );
        memcpy( pTmp, binVal.pVal, binVal.nLen );
        pTmp[binVal.nLen] = 0x00;
        strPrint = pTmp;

        JS_free( pTmp );
    }
    else if( nType == KMIP_TYPE_ENUMERATION )
    {
        int num = JS_BIN_int( &binVal );
        strPrint = QString( "%1" ).arg(num);
    }
    else
    {
        strPrint = getValueHex( pTTLV );
    }

    return strPrint;
}

void TTLVTreeItem::dataReset()
{
    JS_BIN_reset( &header_ );
}
