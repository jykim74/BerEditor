/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef BER_ITEM_H
#define BER_ITEM_H

#include <QStandardItem>
#include "js_bin.h"
#include "js_ber.h"

enum {
    JS_VALUE_HEX = 0,
    JS_VALUE_OID,
    JS_VALUE_NULL,
    JS_VALUE_INTEGER,
    JS_VALUE_STRING,
    JS_VALUE_BITSTRING,
    JS_VALUE_BOOLEAN
};

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
    int GetValLength();
    int GetNonCanonical() { return non_canonical_; };
    BYTE* GetHeader() { return header_; };
    int GetHeaderSize() { return header_size_; };
    int GetOffset() { return offset_; };
    int GetLevel() { return level_; };
    int GetItemSize() { return (header_size_ + length_); };


    QString GetTagString();
    QString GetTagXMLString();
    QString GetClassString();
    QString GetValueString( const BIN *pBer, int *pnType, int nWidth = -1 );
    QString GetValueString( const BIN *pBer, int nWidth = -1 );
    QString GetInfoString( const BIN *pBer );
    BYTE GetDataPos( const BIN *pBer, int nPos );

    int changeLength( int nNewLen, int *pnDiffLen );
    int getHeaderBin( BIN *pHeader );
    int getValueBin( const BIN *pBer, BIN *pValue );
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
