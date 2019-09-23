#ifndef BER_DEFINE_H
#define BER_DEFINE_H

#ifndef TRUE
  #define FALSE	0
  #define TRUE	( !FALSE )
#endif /* TRUE */

#ifndef BYTE
typedef unsigned char   BYTE;
#endif

#define JS_LENGTH_MAGIC	177545L

/* Tag classes */

#define JS_CLASS_MASK		0xC0	/* Bits 8 and 7 */
#define JS_UNIVERSAL		0x00	/* 0 = Universal (defined by ITU X.680) */
#define JS_APPLICATION		0x40	/* 1 = Application */
#define JS_CONTEXT			0x80	/* 2 = Context-specific */
#define JS_PRIVATE			0xC0	/* 3 = Private */

/* Encoding type */

#define JS_FORM_MASK		0x20	/* Bit 6 */
#define JS_PRIMITIVE		0x00	/* 0 = primitive */
#define JS_CONSTRUCTED		0x20	/* 1 = constructed */

/* Universal tags */

#define JS_TAG_MASK		0x1F	/* Bits 5 - 1 */
#define JS_EOC				0x00	/*  0: End-of-contents octets */
#define JS_BOOLEAN			0x01	/*  1: Boolean */
#define JS_INTEGER			0x02	/*  2: Integer */
#define JS_BITSTRING		0x03	/*  2: Bit string */
#define JS_OCTETSTRING		0x04	/*  4: Byte string */
#define JS_NULLTAG			0x05	/*  5: NULL */
#define JS_OID				0x06	/*  6: Object Identifier */
#define JS_OBJDESCRIPTOR	0x07	/*  7: Object Descriptor */
#define JS_EXTERNAL		0x08	/*  8: External */
#define JS_REAL			0x09	/*  9: Real */
#define JS_ENUMERATED		0x0A	/* 10: Enumerated */
#define JS_EMBEDDED_PDV	0x0B	/* 11: Embedded Presentation Data Value */
#define JS_UTF8STRING		0x0C	/* 12: UTF8 string */
#define JS_SEQUENCE		0x10	/* 16: Sequence/sequence of */
#define JS_SET				0x11	/* 17: Set/set of */
#define JS_NUMERICSTRING	0x12	/* 18: Numeric string */
#define JS_PRINTABLESTRING	0x13	/* 19: Printable string (ASCII subset) */
#define JS_T61STRING		0x14	/* 20: T61/Teletex string */
#define JS_VIDEOTEXSTRING	0x15	/* 21: Videotex string */
#define JS_IA5STRING		0x16	/* 22: IA5/ASCII string */
#define JS_UTCTIME			0x17	/* 23: UTC time */
#define JS_GENERALIZEDTIME	0x18	/* 24: Generalized time */
#define JS_GRAPHICSTRING	0x19	/* 25: Graphic string */
#define JS_VISIBLESTRING	0x1A	/* 26: Visible string (ASCII subset) */
#define JS_GENERALSTRING	0x1B	/* 27: General string */
#define JS_UNIVERSALSTRING	0x1C	/* 28: Universal string */
#define JS_BMPSTRING		0x1E	/* 30: Basic Multilingual Plane/Unicode string */

/* Length encoding */

#define JS_LEN_XTND  0x80		/* Indefinite or long form */
#define JS_LEN_MASK  0x7F		/* Bits 7 - 1 */

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_URL
};

enum {
    ENC_ENCRYPT,
    ENC_DECRYPT
};

enum {
    SIGN_SIGNATURE,
    SIGN_VERIFY
};

#endif // BER_DEFINE_H
