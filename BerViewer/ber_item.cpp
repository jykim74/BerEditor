#include "ber_item.h"
#include "js_bin.h"
#include "js_pki_tools.h"


BerItem::BerItem()
{
    id_ = -1;
    tag_ = -1;
    indefinite_ = 0;
    non_canonical_ = 0;

    memset( header_, 0x00, sizeof(header_));
    offset_ = -1;
    level_ = -1;

    setEditable(false);
}

void BerItem::SetId( int id )
{
    id_ = id;
}

void BerItem::SetTag( int tag )
{
    tag_ = tag;
}

void BerItem::SetIndefinite( int indefinite )
{
    indefinite_ = indefinite;
}

void BerItem::SetNonCanonical( int non_cononical )
{
    non_canonical_ = non_cononical;
}

void BerItem::SetHeader( BYTE *pHeader, int len )
{
    if( len > 8 ) return;

    memcpy( header_, pHeader, len );
}

void BerItem::SetHeaderByte( BYTE ch, int pos )
{
    if( pos > 8 ) return;

    header_[pos] = ch;
}

void BerItem::SetOffset( int offset )
{
    offset_ = offset;
}

void BerItem::SetHeaderSize(int size)
{
    header_size_ = size;
}

void BerItem::SetLength(int length)
{
    length_ = length;
}

void BerItem::SetLevel(int level)
{
    level_ = level;
}

QString BerItem::GetTagString()
{
    QString strRes;

    if( id_ < 0 ) return "Error";

    if( id_ & JS_CLASS_MASK )
    {
        QString strOut = "";

        if( id_ & JS_CONTEXT ) strOut.sprintf( "Context-specific[%0x]", tag_);
        else if( id_ & JS_APPLICATION ) strOut.sprintf( "Application[%0x]", tag_ );
        else if( id_ & JS_PRIVATE ) strOut.sprintf( "Private[%0x]", tag_ );

        return strOut;
    }
    else
    {
        if( tag_ == JS_BOOLEAN ) return "BOOLEAN";
        else if( tag_ == JS_INTEGER ) return "INTEGER";
        else if( tag_ == JS_BITSTRING ) return "BITSTRING";
        else if( tag_ == JS_OCTETSTRING ) return "OCTETSTRING";
        else if( tag_ == JS_NULLTAG ) return "NULL";
        else if( tag_ == JS_OID ) return "OID";
        else if( tag_ == JS_OBJDESCRIPTOR ) return "OBJDESCRIPTOR";
        else if( tag_ == JS_EXTERNAL ) return "EXTERNAL";
        else if( tag_ == JS_REAL ) return "REAL";
        else if( tag_ == JS_ENUMERATED ) return "ENUMERATED";
        else if( tag_ == JS_EMBEDDED_PDV ) return "EMBEDDED_PDV";
        else if( tag_ == JS_UTF8STRING ) return "UTF8STRING";
        else if( tag_ == JS_SEQUENCE) return "SEQUENCE(OF)";
        else if( tag_ == JS_SET) return "SET(OF)";
        else if( tag_ == JS_NUMERICSTRING ) return "NUMERICSTR";
        else if( tag_ == JS_PRINTABLESTRING ) return "PRINTABLESTRING";
        else if( tag_ == JS_T61STRING ) return "T61STRING";
        else if( tag_ == JS_VIDEOTEXSTRING ) return "VIDEOTEXSTRING";
        else if( tag_ == JS_IA5STRING ) return "IA5STRING";
        else if( tag_ == JS_UTCTIME ) return "UTCTIME";
        else if( tag_ == JS_GENERALIZEDTIME ) return "GENERALIZEDTIME";
        else if( tag_ == JS_GRAPHICSTRING) return "GRAPHICSTRING";
        else if( tag_ == JS_VISIBLESTRING) return "VISIBLESTRING";
        else if( tag_ == JS_GENERALSTRING) return "GENERALSTRING";
        else if( tag_ == JS_UNIVERSALSTRING ) return "UNIVERSALSTRING";
        else if( tag_ == JS_BMPSTRING ) return "BMPSTRING";
        else
        {
            QString strTag;
            strTag.sprintf ( "%0x", tag_ );
            return strTag;
        }
    }

    return strRes;
}

QString BerItem::GetClassString()
{
    if( id_ & JS_CLASS_MASK )
    {
        if( id_ & JS_CONTEXT ) return "Context-specific";
        else if( id_ & JS_APPLICATION ) return "Application";
        else if( id_ & JS_PRIVATE ) return "Private";
    }
    else {
        return "Universal";
    }

    return "Application";
}

QString BerItem::GetValueString( const BIN *pBer )
{
    QString strVal;
    BIN     binVal = {0,0};

    JS_BIN_set( &binVal, pBer->pVal + offset_ + header_size_, length_ );

    if( tag_ == JS_OID )
    {
        char sOID[1024];
        JS_PKI_getStringFromOID( &binVal, sOID );
        strVal = sOID;
    }
    else if( tag_ == JS_NULLTAG )
    {
        strVal = "NULL";
    }
    else if( tag_ == JS_INTEGER )
    {
        char *pDecimal = NULL;
        JS_PKI_binToDecimal( &binVal, &pDecimal );
        if( pDecimal )
        {
            strVal = pDecimal;
            JS_free( pDecimal );
        }
    }
    else if( tag_ == JS_PRINTABLESTRING || tag_ == JS_IA5STRING || tag_ == JS_UTF8STRING \
             || tag_ == JS_UTCTIME || tag_ == JS_GENERALIZEDTIME )
    {
        char *pStr = NULL;
        pStr = (char *)JS_calloc(1, binVal.nLen + 1 );
        memcpy( pStr, binVal.pVal, binVal.nLen );
        strVal = pStr;
        JS_free(pStr);
    }
    else if( tag_ == JS_BITSTRING )
    {
        int iUnused = 0;
        char *pBitStr = (char *)JS_malloc( binVal.nLen * 8 + 8 );
        JS_PKI_getBitString( &binVal, &iUnused, pBitStr );
        strVal = pBitStr;
//        strVal.sprintf( "%s(%d bits unused)", pBitStr, iUnused );
        JS_free(pBitStr);
    }
    else {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binVal, &pHex );
        strVal = pHex;
        if( pHex ) JS_free(pHex);
    }

    JS_BIN_reset( &binVal );
    return strVal;
}

QString BerItem::GetInfoString(const BIN *pBer)
{
    QString strMsg;
    QString strTag = GetTagString();
    QString strVal;

    strMsg = strTag;

    if( id_ & JS_CLASS_MASK ) return strMsg;

    if( tag_ == JS_OID )
    {
        strVal = GetValueString(pBer);
        strMsg = QString( "%1 %2(%3)" ).arg(strTag).arg(JS_PKI_getSNFromOID(strVal.toStdString().c_str())).arg(strVal);
    }
    else if( tag_ == JS_INTEGER )
    {
        strVal = GetValueString(pBer);
        if( strVal.length() > 16 )
        {
            strVal = strVal.mid(0,15);
            strVal += "...";
        }

        strMsg = QString( "%1 %2").arg(strTag).arg(strVal);
    }
    else if( tag_ == JS_BITSTRING )
    {
        int iUnused = 0;
        BIN     binVal = {0,0};
        char *pTextBit = NULL;

        JS_BIN_set( &binVal, pBer->pVal + offset_ + header_size_, length_ );

        pTextBit = (char *)JS_malloc( binVal.nLen * 8 + 8 );
        JS_PKI_getBitString( &binVal, &iUnused, pTextBit );

        QString tmpStr = pTextBit;
        if( tmpStr.length() > 16 )
        {
            tmpStr.mid(0,15);
            tmpStr += "...";
        }

        strMsg = QString( "%1 %2(unused %3)").arg( strTag ).arg(tmpStr).arg(iUnused);
        JS_BIN_reset(&binVal);
        if( pTextBit ) JS_free( pTextBit );
    }
    else if( tag_ == JS_PRINTABLESTRING || tag_ == JS_IA5STRING || tag_ == JS_UTF8STRING \
             || tag_ == JS_UTCTIME || tag_ == JS_GENERALIZEDTIME )
    {
        strVal = GetValueString(pBer);
        strMsg = QString( "%1 '%2'").arg( strTag).arg( strVal);
    }

    if( tag_ == 0 && id_ == 0 && length_ == 0 )
        strMsg = "EOC";

    return strMsg;
}
