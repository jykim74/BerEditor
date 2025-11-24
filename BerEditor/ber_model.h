/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef BER_MODEL_H
#define BER_MODEL_H

#include <QStandardItemModel>
#include "ber_item.h"
#include "js_bin.h"

class BerModel : public QStandardItemModel
{
    Q_OBJECT
public:
    BerModel( QObject *parent = 0 );

    void setBER( const BIN *pBer );

    int parseTree( bool bExpand );
    int parseConstruct( int offset, BerItem *pParentItem, bool bExpand );
    int parseIndefiniteConstruct( int offset, BerItem *pParentItem, bool bExpand );

    const BIN& getBER() { return binBer_; };
    int getItem( int offset, BerItem *pItem );
    int getItem( const BIN *pBer, int offset, BerItem *pItem );

    const BerItem* addItem( BerItem* pParentItem, bool bFirst, const BIN *pData );
    int removeItem( BerItem *pItem );
    int modifyItem( BerItem *pItem, const BIN *pValue );
    const BerItem* findItemByOffset( BerItem* pParentItem, int nOffset );

private:
//    int resizeParentHeader( int nDiffLen, const BerItem *pItem, BIN *pBER );

    int resizeItemHead( BIN *pBER, BerItem *pItem, int nModItemLen );
    int resizeHeadToTop( BIN *pBER, BerItem *pItem, int nModItemLen );

    void initialize();

    BIN     binBer_;
};

#endif // BER_MODEL_H
