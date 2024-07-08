#include "js_bin.h"
#include "kmip.h"
#include "js_kms.h"
#include "ttlv_tree_item.h"



TTLVTreeItem::TTLVTreeItem()
{
    tag_ = (BIN *)JS_calloc(1, sizeof(BIN));
    type_ = (BIN *)JS_calloc(1, sizeof(BIN));
    length_ = (BIN *)JS_calloc(1, sizeof(BIN));
    value_ = (BIN *)JS_calloc(1, sizeof(BIN));

    setEditable(false);
}

void TTLVTreeItem::setTag( const BIN *pTag )
{
    JS_BIN_reset( tag_ );

    if( pTag ) JS_BIN_copy( tag_, pTag );
}

void TTLVTreeItem::setType( const BIN *pType )
{
    JS_BIN_reset( type_ );
    if( pType ) JS_BIN_copy( type_, pType );
}

void TTLVTreeItem::setLength( const BIN *pLength )
{
    JS_BIN_reset( length_ );
    if( pLength ) JS_BIN_copy( length_, pLength );
}

void TTLVTreeItem::setValue( const BIN *pValue )
{
    JS_BIN_reset( value_ );
    if( pValue ) JS_BIN_copy( value_, pValue );
}

void TTLVTreeItem::setOffset( int offset )
{
    offset_ = offset;
}

void TTLVTreeItem::setLevel( int level )
{
    level_ = level;
}

QString TTLVTreeItem::getTagHex()
{
    char *pHex = NULL;
    if( tag_ == NULL ) return "";

    JS_BIN_encodeHex( tag_, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

QString TTLVTreeItem::getTypeHex()
{
    char *pHex = NULL;
    if( type_ == NULL ) return "";

    JS_BIN_encodeHex( type_, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

QString TTLVTreeItem::getLengthHex()
{
    char    *pHex = NULL;
    if( length_ == NULL ) return "";

    JS_BIN_encodeHex( length_, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

QString TTLVTreeItem::getValueHex()
{
    char *pHex = NULL;
    if( value_ == NULL ) return "";

    JS_BIN_encodeHex( value_, &pHex );
    QString strHex = pHex;

    if( pHex ) JS_free( pHex );

    return strHex;
}

int32 TTLVTreeItem::getLengthInt()
{

    int32   len = 0;

    len = JS_BIN_int( length_ );

    return len;
}

QString TTLVTreeItem::getTagName()
{
    int nTag = -1;
    QString strName;
    if( tag_ == NULL ) return "";

    nTag = JS_BIN_int( tag_ );

    strName = JS_KMS_tagName( nTag );

    return strName;
}

QString TTLVTreeItem::getTypeName()
{
    int nType = -1;
    QString strName;

    if( type_ == NULL ) return "";

    nType = JS_BIN_int( type_ );

    strName = JS_KMS_typeName( nType );

    return strName;
}

QString TTLVTreeItem::getTitle()
{
    QString strTitle;
    QString strTag = getTagName();
    QString strType = getTypeName();
    int nType = JS_BIN_int( type_ );

    if( nType == KMIP_TYPE_INTEGER ||
            nType == KMIP_TYPE_TEXT_STRING ||
            nType == KMIP_TYPE_ENUMERATION )
    {
        QString strPrint = getPrintValue();
        strTitle = QString( "%1(%2 %3)").arg( strTag ).arg(strType).arg(strPrint);
    }
    else
    {
        strTitle = QString( "%1(%2)").arg( strTag ).arg(strType);
    }

    return strTitle;
}

QString TTLVTreeItem::getPrintValue()
{
    int nType = JS_BIN_int( type_ );
    QString strPrint;

    if( nType == KMIP_TYPE_INTEGER )
    {
        int num = JS_BIN_int( value_ );
        strPrint = QString( "%1" ).arg( num );
    }
    else if( nType == KMIP_TYPE_TEXT_STRING )
    {
        char *pTmp = (char *)JS_malloc( value_->nLen + 1 );
        memcpy( pTmp, value_->pVal, value_->nLen );
        pTmp[value_->nLen] = 0x00;
        strPrint = pTmp;

        JS_free( pTmp );
    }
    else if( nType == KMIP_TYPE_ENUMERATION )
    {
        int num = JS_BIN_int( value_ );
        strPrint = QString( "%1" ).arg(num);
    }
    else
    {
        strPrint = getValueHex();
    }

    return strPrint;
}

void TTLVTreeItem::dataReset()
{
    if( tag_ ) JS_BIN_reset( tag_ );
    if( type_ ) JS_BIN_reset( type_ );
    if( length_ ) JS_BIN_reset( length_ );
    if( value_ ) JS_BIN_reset( value_ );
}
