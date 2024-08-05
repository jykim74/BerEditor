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
    void Unset();

    void showRight();
    void showRightFull( TTLVTreeItem *pItem );
    void showRightPart( TTLVTreeItem *pItem );
    void getInfoView( TTLVTreeItem *pItem, int nWidth );
    QString GetTextView();
/*
    void showTextView();
    void showXMLView();
*/


public slots:
    void CopyAsHex();
    void CopyAsBase64();
    void copy();

    void treeExpandAll();
    void treeExpandNode();
    void treeCollapseAll();
    void treeCollapseNode();

    void AddTTLV();

    void editItem();
    void saveItem();
    void saveItemValue();

private slots:
    void onItemClicked( const QModelIndex& index );
    void leftContextMenu( QPoint point );

    void showItemText( TTLVTreeItem* item, TTLVTreeItem *setItem = nullptr, bool bBold = false );
    void showItemXML( TTLVTreeItem* item, TTLVTreeItem *setItem = nullptr, bool bBold = false );

    void showText( int level, const QString& strMsg, QColor cr = QColor(0x00, 0x00, 0x00), bool bBold = false );
    void showXML( int level, const QString& strMsg, QColor cr = QColor(0x00, 0x00, 0x00), bool bBold = false );

public:
    TTLVTreeItem* currentItem();
    bool is_set_ = false;
};

#endif // READERTREEVIEW_H
