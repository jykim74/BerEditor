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
    void setTTLV( const BIN *pTTLV );
    const BIN& getTTLV() { return binTTLV_; };

    int parseTree();
    int parseConstruct( int offset, TTLVTreeItem *pParentItem );

public slots:


private:
    int getItem( int offset, TTLVTreeItem *pItem );

    BIN binTTLV_;
};

#endif // TTLVTREEMODEL_H
