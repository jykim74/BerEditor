/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "ber_item.h"
#include "common.h"
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

    if( id_ & JS_CONTEXT )
    {
        strRes = QString( "Context-specific[%1]" ).arg( tag_ );
    }
    else
    {
        strRes = JS_BER_getPrimitiveName( tag_ );

        if( strRes.length() < 1 )
        {
            QString strTag;
            strTag = QString( "%1" ).arg( tag_, 2, 16, QLatin1Char( '0' ));
            return strTag;
        }
    }

    return strRes;
}

QString BerItem::GetTagXMLString()
{
    QString strRes;

    if( id_ < 0 ) return "Error";

    if( id_ & JS_CLASS_MASK )
    {
        QString strOut = "CONTEXT";
        return strOut;
    }
    else
    {
        if( tag_ == JS_BOOLEAN ) return "BOOLEAN";
        else if( tag_ == JS_INTEGER ) return "INTEGER";
        else if( tag_ == JS_BITSTRING ) return "BIT_STRING";
        else if( tag_ == JS_OCTETSTRING ) return "OCTET_STRING";
        else if( tag_ == JS_NULLTAG ) return "NULL_TAG";
        else if( tag_ == JS_OID ) return "OBJECT_IDENTIFIER";
        else if( tag_ == JS_OBJDESCRIPTOR ) return "OBJ_DESCRIPTOR";
        else if( tag_ == JS_EXTERNAL ) return "EXTERNAL";
        else if( tag_ == JS_REAL ) return "REAL";
        else if( tag_ == JS_ENUMERATED ) return "ENUMERATED";
        else if( tag_ == JS_EMBEDDED_PDV ) return "EMBEDDED_PDV";
        else if( tag_ == JS_UTF8STRING ) return "UTF8_STRING";
        else if( tag_ == JS_SEQUENCE) return "SEQUENCE";
        else if( tag_ == JS_SET) return "SET";
        else if( tag_ == JS_NUMERICSTRING ) return "NUMERIC_STRING";
        else if( tag_ == JS_PRINTABLESTRING ) return "PRINTABLE_STRING";
        else if( tag_ == JS_T61STRING ) return "T61_STRING";
        else if( tag_ == JS_VIDEOTEXSTRING ) return "VIDEO_TEX_STRING";
        else if( tag_ == JS_IA5STRING ) return "IA5_STRING";
        else if( tag_ == JS_UTCTIME ) return "UTC_TIME";
        else if( tag_ == JS_GENERALIZEDTIME ) return "GENERALIZED_TIME";
        else if( tag_ == JS_GRAPHICSTRING) return "GRAPHIC_STRING";
        else if( tag_ == JS_VISIBLESTRING) return "VISIBLE_STRING";
        else if( tag_ == JS_GENERALSTRING) return "GENERAL_STRING";
        else if( tag_ == JS_UNIVERSALSTRING ) return "UNIVERSAL_STRING";
        else if( tag_ == JS_BMPSTRING ) return "BMP_STRING";
        else
        {
            QString strTag;
            strTag = QString( "%1" ).arg( tag_, 2, 16, QLatin1Char('0'));
            return strTag.toUpper();
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

QString BerItem::GetValueString( const BIN *pBer, int nWidth )
{
    return GetValueString( pBer, NULL, nWidth );
}

QString BerItem::GetValueString( const BIN *pBer, int *pnType, int nWidth )
{
    QString strVal;
    BIN     binVal = {0,0};

//    if( length_ <= 0 ) return strVal;

    JS_BIN_set( &binVal, pBer->pVal + offset_ + header_size_, length_ );

    if( id_ & JS_CLASS_MASK )
    {
        strVal = getHexStringArea( &binVal, nWidth );
        if( pnType ) *pnType = JS_VALUE_HEX;
    }
    else
    {
        if( tag_ == JS_OID )
        {
            char sOID[1024];

            memset( sOID, 0x00, sizeof(sOID));
            JS_PKI_getStringFromOIDValue( &binVal, sOID );
            strVal = sOID;

            if( pnType ) *pnType = JS_VALUE_OID;
        }
        else if( tag_ == JS_NULLTAG )
        {
            strVal = "NULL";
            if( pnType ) *pnType = JS_VALUE_NULL;
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

            if( pnType ) *pnType = JS_VALUE_INTEGER;
        }
        else if( tag_ == JS_PRINTABLESTRING || tag_ == JS_IA5STRING || tag_ == JS_UTF8STRING \
                 || tag_ == JS_UTCTIME || tag_ == JS_GENERALIZEDTIME || tag_ == JS_VISIBLESTRING )
        {
            char *pStr = NULL;
            pStr = (char *)JS_calloc(1, binVal.nLen + 1 );
            memcpy( pStr, binVal.pVal, binVal.nLen );
            strVal = pStr;
            JS_free(pStr);

            if( pnType ) *pnType = JS_VALUE_STRING;
        }
        else if( tag_ == JS_BITSTRING )
        {
            int iUnused = 0;
            char *pBitStr = (char *)JS_malloc( binVal.nLen * 8 + 8 );
            JS_PKI_getBitString( &binVal, &iUnused, pBitStr );
            strVal = pBitStr;
            JS_free(pBitStr);
            strVal = getHexStringArea( strVal, nWidth );

            if( pnType ) *pnType = JS_VALUE_BITSTRING;
        }
        else if( tag_ == JS_BOOLEAN )
        {
            if( binVal.pVal[0] == 0x00 )
                strVal = "False";
            else
                strVal = "True";

            if( pnType ) *pnType = JS_VALUE_BOOLEAN;
        }
        else {
            strVal = getHexStringArea( &binVal, nWidth );
            if( pnType ) *pnType = JS_VALUE_HEX;
        }
    }

    JS_BIN_reset( &binVal );
    return strVal;
}


BYTE BerItem::GetDataPos( const BIN *pBer, int nPos )
{
    if( nPos > (offset_ + header_size_ + length_) ) return -1;

    BYTE ch = pBer->pVal[offset_ + header_size_ + nPos];
    return ch;
}

QString BerItem::GetInfoString(const BIN *pBer)
{
    QString strMsg;
    QString strTag = GetTagString();
    QString strVal;

    strMsg = strTag;

//    if( id_ & JS_CLASS_MASK ) return strMsg;
    if( id_ & JS_CONTEXT ) return strMsg;

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
            tmpStr = tmpStr.mid(0,15);
            tmpStr += "...";
        }

//        strMsg = QString( "%1 %2(unused %3)").arg( strTag ).arg(tmpStr).arg(iUnused);
        strMsg = QString( "%1(%2 bits) %3(unused %4)").arg( strTag ).arg( strlen(pTextBit )).arg( tmpStr ).arg(iUnused);
        JS_BIN_reset(&binVal);
        if( pTextBit ) JS_free( pTextBit );
    }
    else if( tag_ == JS_PRINTABLESTRING || tag_ == JS_IA5STRING || tag_ == JS_UTF8STRING \
             || tag_ == JS_UTCTIME || tag_ == JS_GENERALIZEDTIME )
    {
        strVal = GetValueString(pBer);
        strMsg = QString( "%1 '%2'").arg( strTag).arg( strVal);
    }
    else if( tag_ == JS_BOOLEAN )
    {
        strVal = GetValueString( pBer );
        strMsg = QString( "%1(%2)").arg( strTag ).arg( strVal );
    }

    if( tag_ == 0 && id_ == 0 && length_ == 0 )
        strMsg = "EOC";

    return strMsg;
}

int BerItem::changeLength( int nNewLen, int *pnDiffLen )
{
    int nDiff = 0;
    int nCurHeaderSize = header_size_;

    if( length_ == nNewLen )
    {
        *pnDiffLen = 0;
        return 0;
    }

    nDiff = nNewLen - length_;

    if( indefinite_ == true ) return nDiff;

    if( nNewLen <= 127 )
    {
        header_size_ = 2;
        header_[1] = nNewLen;
    }
    else if( nNewLen <= 255 )
    {
        header_size_ = 3;
        header_[1] = 0x81;
        header_[2] = nNewLen & 0xFF;
    }
    else if( nNewLen <= 65535 )
    {
        header_size_ = 4;
        header_[1] = 0x82;
        header_[2] = (nNewLen >> 8) & 0xFF;
        header_[3] = nNewLen & 0xFF;
    }
    else if( nNewLen <= 1677215 )
    {
        header_size_ = 5;
        header_[1] = 0x83;
        header_[2] = (nNewLen >> 16) & 0xFF;
        header_[3] = (nNewLen >> 8) & 0xFF;
        header_[4] = nNewLen & 0xFF;
    }
    else if( nNewLen <= 2147483647 )
    {
        header_size_ = 6;
        header_[1] = 0x84;
        header_[2] = (nNewLen >> 24) & 0xFF;
        header_[3] = (nNewLen >> 16) & 0xFF;
        header_[4] = (nNewLen >> 8) & 0xFF;
        header_[5] = nNewLen & 0xFF;
    }
    else
    {
        return -1;
    }

    nDiff += (header_size_ - nCurHeaderSize);
    *pnDiffLen = nDiff;

    return 0;
}

int BerItem::getHeaderBin( BIN *pHeader )
{
    if( pHeader == NULL ) return -1;

    JS_BIN_set( pHeader, header_, header_size_ );
    return 0;
}

int BerItem::getValueBin( const BIN *pBer, BIN *pValue )
{
    if( pBer == NULL || pValue == NULL ) return -1;

    JS_BIN_set( pValue, pBer->pVal + offset_ + header_size_, length_ );
    return 0;
}

bool BerItem::isConstructed()
{
    if( id_ & JS_CONSTRUCTED )
        return true;
    else
        return false;
}
