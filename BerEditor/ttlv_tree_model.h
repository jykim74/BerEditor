#ifndef TTLVTREEMODEL_H
#define TTLVTREEMODEL_H

#include <QStandardItemModel>
#include "js_bin.h"

class TTLVTreeItem;

class TTLVTreeModel : public QStandardItemModel
{
    Q_OBJECT

public:
    TTLVTreeModel( QObject *parent = 0 );
    ~TTLVTreeModel();

    void setTTLV( const BIN *pTTLV );
    const BIN& getTTLV() { return binTTLV_; };

    int parseTree();
    int parseConstruct( int offset, TTLVTreeItem *pParentItem );

    int addItem( TTLVTreeItem* pParentItem, const BIN *pData );
    int removeItem( TTLVTreeItem *pItem );
    int modifyItem( TTLVTreeItem *pItem, const BIN *pValue );

private:
    int getItem( int offset, TTLVTreeItem *pItem );
    int resizeParentHeader( int nDiffLen, const TTLVTreeItem *pItem, BIN* pTTLV );

    BIN binTTLV_;
};

#endif // TTLVTREEMODEL_H
