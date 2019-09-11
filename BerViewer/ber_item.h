#ifndef BER_ITEM_H
#define BER_ITEM_H

#include <QStandardItem>
#include "js_bin.h"

#ifndef TRUE
  #define FALSE	0
  #define TRUE	( !FALSE )
#endif /* TRUE */

#ifndef BYTE
typedef unsigned char   BYTE;
#endif

#define LENGTH_MAGIC	177545L

/* Tag classes */

#define CLASS_MASK		0xC0	/* Bits 8 and 7 */
#define UNIVERSAL		0x00	/* 0 = Universal (defined by ITU X.680) */
#define APPLICATION		0x40	/* 1 = Application */
#define CONTEXT			0x80	/* 2 = Context-specific */
#define PRIVATE			0xC0	/* 3 = Private */

/* Encoding type */

#define FORM_MASK		0x20	/* Bit 6 */
#define PRIMITIVE		0x00	/* 0 = primitive */
#define CONSTRUCTED		0x20	/* 1 = constructed */

/* Universal tags */

#define TAG_MASK		0x1F	/* Bits 5 - 1 */
#define EOC				0x00	/*  0: End-of-contents octets */
#define BOOLEAN			0x01	/*  1: Boolean */
#define INTEGER			0x02	/*  2: Integer */
#define BITSTRING		0x03	/*  2: Bit string */
#define OCTETSTRING		0x04	/*  4: Byte string */
#define NULLTAG			0x05	/*  5: NULL */
#define OID				0x06	/*  6: Object Identifier */
#define OBJDESCRIPTOR	0x07	/*  7: Object Descriptor */
#define EXTERNAL		0x08	/*  8: External */
#define REAL			0x09	/*  9: Real */
#define ENUMERATED		0x0A	/* 10: Enumerated */
#define EMBEDDED_PDV	0x0B	/* 11: Embedded Presentation Data Value */
#define UTF8STRING		0x0C	/* 12: UTF8 string */
#define SEQUENCE		0x10	/* 16: Sequence/sequence of */
#define SET				0x11	/* 17: Set/set of */
#define NUMERICSTRING	0x12	/* 18: Numeric string */
#define PRINTABLESTRING	0x13	/* 19: Printable string (ASCII subset) */
#define T61STRING		0x14	/* 20: T61/Teletex string */
#define VIDEOTEXSTRING	0x15	/* 21: Videotex string */
#define IA5STRING		0x16	/* 22: IA5/ASCII string */
#define UTCTIME			0x17	/* 23: UTC time */
#define GENERALIZEDTIME	0x18	/* 24: Generalized time */
#define GRAPHICSTRING	0x19	/* 25: Graphic string */
#define VISIBLESTRING	0x1A	/* 26: Visible string (ASCII subset) */
#define GENERALSTRING	0x1B	/* 27: General string */
#define UNIVERSALSTRING	0x1C	/* 28: Universal string */
#define BMPSTRING		0x1E	/* 30: Basic Multilingual Plane/Unicode string */

/* Length encoding */

#define LEN_XTND  0x80		/* Indefinite or long form */
#define LEN_MASK  0x7F		/* Bits 7 - 1 */

class BerItem : public QStandardItem
{
public:
    BerItem();

    void SetId( int id );
    void SetTag( int tag );
    void SetIndefinite( int indefinite );
    void SetNonCanonical( int non_cononical );
    void SetHeader( BYTE *pHeader, int len );
    void SetHeaderByte( BYTE ch, int pos );
    void SetOffset( int offset );
    void SetHeaderSize( int size );
    void SetLength( int length );
    void SetLevel( int level );

    int GetId() { return id_; };
    int GetTag() { return tag_; };
    int GetIndefinite() { return indefinite_; };
    int GetLength() { return length_; };
    int GetNonCanonical() { return non_canonical_; };
    BYTE* GetHeader() { return header_; };
    int GetHeaderSize() { return header_size_; };
    int GetOffset() { return offset_; };
    int GetLevel() { return level_; };

    QString GetTagString();
    QString GetClassString();
    QString GetValueString( const BIN *pBer );
    QString GetInfoString( const BIN *pBer );

public:
    int     id_;
    int     tag_;
    long    length_;
    int     indefinite_;
    int     non_canonical_;
    BYTE    header_[16];
    int     header_size_;
    int     offset_;
    int     level_;
};

#endif // BER_ITEM_H
