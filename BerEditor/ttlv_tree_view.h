#ifndef TTLVTREEVIEW_H
#define TTLVTREEVIEW_H

#include <QTreeView>

class TTLVTreeItem;

class TTLVTreeView : public QTreeView
{
    Q_OBJECT

public:
    TTLVTreeView( QWidget* parent = 0 );
    void viewRoot();
    void viewCurrent();
    void expandToTop( const TTLVTreeItem *pItem );


    void getInfoView( TTLVTreeItem *pItem, int nWidth );
    QString GetTextView();


public slots:
    void CopyAsHex();
    void CopyAsBase64();
    void copy();

    void treeExpandAll();
    void treeExpandNode();
    void treeCollapseAll();
    void treeCollapseNode();

    void InsertTTLV();
    void EditItem();
    void DeleteItem();

    const QString saveItem();
    void saveItemValue();

private slots:
    void onItemClicked( const QModelIndex& index );
    void leftContextMenu( QPoint point );

private :
    void setItemText( int level, TTLVTreeItem* item, TTLVTreeItem *setItem = nullptr );
    void setItemXML( int level, TTLVTreeItem* item, TTLVTreeItem *setItem = nullptr );
    void setItemJSON( int level, TTLVTreeItem* item, bool bNext, TTLVTreeItem *setItem = nullptr );

    void addEdit( int level, const QString& strMsg );
#ifdef OLD_TREE
    void showRight();
    void showRightFull( TTLVTreeItem *pItem );
    void showRightPart( TTLVTreeItem *pItem );
#endif
    void viewTable( TTLVTreeItem *pItem, bool bPart = false );
    void viewHex( TTLVTreeItem *pItem, bool bPart );
    void viewXML( TTLVTreeItem *pItem, bool bPart );
    void viewText( TTLVTreeItem *pItem, bool bPart );
    void viewJSON( TTLVTreeItem *pItem, bool bPart );

    QString str_edit_;
    int pos_start_;
    int pos_end_;

public:
    TTLVTreeItem* currentItem();
};

#endif // READERTREEVIEW_H
