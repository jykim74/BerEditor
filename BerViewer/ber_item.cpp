#include "ber_item.h"
#include "js_bin.h"

static int oidToString( char *textOID, const BIN *pOID )
{
    BYTE uuidBuffer[ 32 ];
    long value;
    int length = 0, uuidBufPos = -1, uuidBitCount = 5, i;
    int validEncoding = TRUE, isUUID = FALSE;

    for( i = 0, value = 0; i < pOID->nLen; i++ )
        {
        const BYTE data = pOID->pVal[ i ];
        const long valTmp = value << 7;

        /* Pick apart the encoding.  We keep going after hitting an encoding
           error at the start of an arc because the overall length is
           bounded and we may still be able to recover something worth
           printing */
        if( value == 0 && data == 0x80 )
            {
            /* Invalid leading zero value, 0x80 & 0x7F == 0 */
            validEncoding = FALSE;
            }
        if( isUUID )
            {
            value = 1;	/* Set up dummy value since we're bypassing normal read */
            if( uuidBitCount == 0 )
                uuidBuffer[ uuidBufPos ] = data << 1;
            else
                {
                if( uuidBufPos >= 0 )
                    uuidBuffer[ uuidBufPos ] |= ( data & 0x7F ) >> ( 7 - uuidBitCount );
                uuidBufPos++;
                if( uuidBitCount < 7 )
                    uuidBuffer[ uuidBufPos ] = data << ( uuidBitCount + 1 );
                }
            uuidBitCount++;
            if( uuidBitCount > 7 )
                uuidBitCount = 0;
            if( !( data & 0x80 ) )
                {
                /* The following check isn't completely accurate since we
                   could have less than 16 bytes present if there are
                   leading zeroes, however to handle this properly we'd
                   have to decode the entire value as a bignum and then
                   format it appropriately, and given the fact that the use
                   of these things is practically nonexistent it's probably
                   not worth the code space to deal with this */
                if( uuidBufPos != 16 )
                    {
                    validEncoding = FALSE;
                    break;
                    }
                length += sprintf( textOID + length,
                                   " { %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x }",
                                   uuidBuffer[ 0 ], uuidBuffer[ 1 ],
                                   uuidBuffer[ 2 ], uuidBuffer[ 3 ],
                                   uuidBuffer[ 4 ], uuidBuffer[ 5 ],
                                   uuidBuffer[ 6 ], uuidBuffer[ 7 ],
                                   uuidBuffer[ 8 ], uuidBuffer[ 9 ],
                                   uuidBuffer[ 10 ], uuidBuffer[ 11 ],
                                   uuidBuffer[ 12 ], uuidBuffer[ 13 ],
                                   uuidBuffer[ 14 ], uuidBuffer[ 15 ] );
                value = 0;
                }
            continue;
            }
        if( value >= ( LONG_MAX >> 7 ) || \
            valTmp >= LONG_MAX - ( data & 0x7F ) )
            {
            validEncoding = FALSE;
            break;
            }
        value = valTmp | ( data & 0x7F );
        if( value < 0 || value > LONG_MAX / 2 )
            {
            validEncoding = FALSE;
            break;
            }
        if( !( data & 0x80 ) )
            {
            if( length == 0 )
                {
                long x, y;

                /* The first two levels are encoded into one byte since the
                   root level has only 3 nodes (40*x + y), however if x =
                   joint-iso-itu-t(2) then y may be > 39, so we have to add
                   special-case handling for this */
                x = value / 40;
                y = value % 40;
                if( x > 2 )
                    {
                    /* Handle special case for large y if x == 2 */
                    y += ( x - 2 ) * 40;
                    x = 2;
                    }
                if( x < 0 || x > 2 || y < 0 || \
                    ( ( x < 2 && y > 39 ) || \
                      ( x == 2 && ( y > 50 && y != 100 ) ) ) )
                    {
                    /* If x = 0 or 1 then y has to be 0...39, for x = 3
                       it can take any value but there are no known
                       assigned values over 50 except for one contrived
                       example in X.690 which sets y = 100, so if we see
                       something outside this range it's most likely an
                       encoding error rather than some bizarre new ID
                       that's just appeared */
                    validEncoding = FALSE;
                    break;
                    }
                length = sprintf( textOID, "%ld %ld", x, y );

                /* An insane ITU facility lets people register UUIDs as OIDs
                   (see http://www.itu.int/ITU-T/asn1/uuid.html), if we find
                   one of these, which live under the arc '2 25' = 0x69 we
                   have to continue decoding the OID as a UUID instead of a
                   standard OID */
                if( data == 0x69 )
                    isUUID = TRUE;
                }
            else
                length += sprintf( textOID + length, " %ld", value );
            value = 0;
            }
        }
    if( value != 0 )
        {
        /* We stopped in the middle of a continued value */
        validEncoding = FALSE;
        }
    textOID[ length ] = '\0';

    return( validEncoding );
}


BerItem::BerItem()
{
    id_ = -1;
    tag_ = -1;
    indefinite_ = 0;
    non_canonical_ = 0;

    memset( header_, 0x00, sizeof(header_));
    offset_ = -1;
    level_ = -1;
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

    if( id_ & CLASS_MASK )
    {
        QString strOut = "";

        if( id_ & CONTEXT ) strOut.sprintf( "Context-specific[%0x]", tag_);
        else if( id_ & APPLICATION ) strOut.sprintf( "Application[%0x]", tag_ );
        else if( id_ & PRIVATE ) strOut.sprintf( "Private[%0x]", tag_ );

        return strOut;
    }
    else
    {
        if( tag_ == BOOLEAN ) return "BOOLEAN";
        else if( tag_ == INTEGER ) return "INTEGER";
        else if( tag_ == BITSTRING ) return "BITSTRING";
        else if( tag_ == OCTETSTRING ) return "OCTETSTRING";
        else if( tag_ == NULLTAG ) return "NULL";
        else if( tag_ == OID ) return "OID";
        else if( tag_ == OBJDESCRIPTOR ) return "OBJDESCRIPTOR";
        else if( tag_ == EXTERNAL ) return "EXTERNAL";
        else if( tag_ == REAL ) return "REAL";
        else if( tag_ == ENUMERATED ) return "ENUMERATED";
        else if( tag_ == EMBEDDED_PDV ) return "EMBEDDED_PDV";
        else if( tag_ == UTF8STRING ) return "UTF8STRING";
        else if( tag_ == SEQUENCE) return "SEQUENCE(OF)";
        else if( tag_ == SET) return "SET(OF)";
        else if( tag_ == NUMERICSTRING ) return "NUMERICSTR";
        else if( tag_ == PRINTABLESTRING ) return "PRINTABLESTRING";
        else if( tag_ == T61STRING ) return "T61STRING";
        else if( tag_ == VIDEOTEXSTRING ) return "VIDEOTEXSTRING";
        else if( tag_ == IA5STRING ) return "IA5STRING";
        else if( tag_ == UTCTIME ) return "UTCTIME";
        else if( tag_ == GENERALIZEDTIME ) return "GENERALIZEDTIME";
        else if( tag_ == GRAPHICSTRING) return "GRAPHICSTRING";
        else if( tag_ == VISIBLESTRING) return "VISIBLESTRING";
        else if( tag_ == GENERALSTRING) return "GENERALSTRING";
        else if( tag_ == UNIVERSALSTRING ) return "UNIVERSALSTRING";
        else if( tag_ == BMPSTRING ) return "BMPSTRING";
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
    if( id_ & CLASS_MASK )
    {
        if( id_ & CONTEXT ) return "Context-specific";
        else if( id_ & APPLICATION ) return "Application";
        else if( id_ & PRIVATE ) return "Private";
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
    char    *pHex = NULL;

    JS_BIN_set( &binVal, pBer->pVal + offset_ + header_size_, length_ );


    JS_BIN_encodeHex( &binVal, &pHex );
    strVal = pHex;
    if( pHex ) JS_free(pHex);

    return strVal;
}
