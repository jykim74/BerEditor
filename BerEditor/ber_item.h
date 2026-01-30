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

    void SetIndefinite( int indefinite );
    void SetHeader( BYTE *pHeader, int len );
    void SetHeaderByte( BYTE ch, int pos );
    void SetOffset( int offset );
    void SetHeaderSize( int size );
    void SetLength( int length );
    void SetLevel( int level );

    bool isEOC();
    bool isType( int nType );
    bool isConstructed();

    const BYTE GetId();
    const BYTE GetTag();
    const int GetType();
    const int GetClass();
    const int GetIndefinite() { return indefinite_; };
    const int GetLength() { return length_; };
    int GetValLength();
    BYTE* GetHeader() { return header_; };
    const int GetHeaderSize() { return header_size_; };
    const int GetOffset() { return offset_; };
    const int GetLevel() { return level_; };
    const int GetItemSize() { return (header_size_ + length_); };


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
    int getNodeBin( const BIN *pBer, BIN *pNode );


public:
    long    length_;
    int     indefinite_;
    BYTE    header_[16];
    int     header_size_;
    int     offset_;
    int     level_;
};

#endif // BER_ITEM_H
