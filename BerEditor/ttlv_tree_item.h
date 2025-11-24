#ifndef TTLVTREEITEM_H
#define TTLVERTREEITEM_H

#include "kmip.h"
#include "js_bin.h"

#include <QStandardItem>

#define JS_TTLV_HEADER_SIZE     8
#define JS_TTLV_TAG_SIZE        3
#define JS_TTLV_TYPE_SIZE       1
#define JS_TTLV_LENGTH_SIZE     4

#define JS_TTLV_TAG_OFFSET      0
#define JS_TTLV_TYPE_OFFSET     3
#define JS_TTLV_LENGTH_OFFSET   4

class TTLVTreeItem : public QStandardItem
{
public:
    TTLVTreeItem();
    ~TTLVTreeItem();

    int getOffset() { return offset_; };
    int getLevel() { return level_; };

    void setHeader( const unsigned char *pValue, int nLength );
    void setOffset( int offset );
    void setLevel( int level );

    int getHeader( BIN *pHeader );
    int getTag( BIN *pTag );
    int getType( BIN *pType );
    int getLength( BIN *pLength );
    int setLength( int32 nLength );
    int getValue( const BIN *pTTLV, BIN *pValue );
    int getValueWithPad( const BIN *pTTLV, BIN *pValue );
    int getDataAll( const BIN *pTTLV, BIN *pData );

    QString getTagHex();
    QString getTypeHex();
    int getType();
    QString getLengthHex();
    QString getValueHex( const BIN *pTTLV );
    int32 getLengthInt();
    int32 getLengthWithPad();
    int32 getLengthTTLV();
    QString getTagName();
    QString getTypeName();
    QString getTitle( const BIN *pTTLV );
    QString getPrintValue( const BIN *pTTLV, int *pnType, int nWidth = -1 );
    QString getPrintValue( const BIN *pTTLV, int nWidth = -1 );

    void dataReset();
    bool isStructure();

public:
    BIN     header_;
    int     offset_;
    int     level_;
};

#endif // TTLVTREEITEM_H
