#ifndef BER_ITEM_H
#define BER_ITEM_H

#include <QStandardItem>
#include "js_bin.h"
#include "js_ber.h"


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

    int changeLength( int nNewLen, int *pnDiffLen );
    int getHeaderBin( BIN *pHeader );
    bool isConstructed();

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
