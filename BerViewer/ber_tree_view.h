#ifndef BER_TREE_VIEW_H
#define BER_TREE_VIEW_H

#include <QTreeView>
#include <QTextBrowser>
#include <QTableWidget>
#include "js_bin.h"

class BerItem;

class BerTreeView : public QTreeView
{
    Q_OBJECT
public:
    BerTreeView( QWidget* parent = 0 );

    void viewRoot();
    QString GetTextView();


private slots:
    void onItemClicked( const QModelIndex& index );
    void ShowContextMenu( QPoint point );
    void ExpandValue();
    void SaveNode();
    void SaveNodeValue();
    void EditValue();
    void InsertBER();


public slots:
    void CopyAsHex();
    void CopyAsBase64();
    void copy();

    void treeExpandAll();
    void treeExpandNode();
    void treeCollapseAll();
    void treeCollapseNode();

private:

    QString GetInfoView( const BIN *pBer, BerItem *pItem );
    QString GetDataView( const BIN *pData, const BerItem *pItem );
    void GetTableView( const BIN *pBer, BerItem *pItem );
    void GetTableFullView( const BIN *pBer, BerItem *pItem );

    BerItem* currentItem();
};

#endif // BER_TREE_VIEW_H
