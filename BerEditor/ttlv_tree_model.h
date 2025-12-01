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

    const TTLVTreeItem* addItem( TTLVTreeItem* pParentItem, bool bFirst, const BIN *pData );
    int removeItem( TTLVTreeItem *pItem );
    int modifyItem( TTLVTreeItem *pItem, const BIN *pValue );
    const TTLVTreeItem* findItemByOffset( TTLVTreeItem* pParentItem, int nOffset );

    const TTLVTreeItem* findNextItemByValue( const TTLVTreeItem* pItem, const BIN *pValue, bool bMatched = false );
    const TTLVTreeItem* findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pValue, bool bMatched = false );
    const TTLVTreeItem* findNextItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched = false );
    const TTLVTreeItem* findPrevItemByValue( const TTLVTreeItem* pItem, const BIN *pHeader, const BIN *pValue, bool bMatched = false );

    void selectValue( TTLVTreeItem *pItem, const BIN *pValue, bool bPart = false );

private:
    int getItem( int offset, TTLVTreeItem *pItem );
    int getItem( BIN *pTTLV, int offset, TTLVTreeItem *pItem );
    void getTablePosition( int nOffset, int *pRow, int *pCol );

    int resizeParentHeader( int nDiffLen, const TTLVTreeItem *pItem, BIN* pTTLV );

    BIN binTTLV_;
};

#endif // TTLVTREEMODEL_H
