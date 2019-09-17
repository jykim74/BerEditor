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
    void setTextEdit( QTextEdit *txtEdit );
    void setTable( QTableWidget *table );

private slots:
    void onItemClicked( const QModelIndex& index );
    void ShowContextMenu( QPoint point );
    void CopyAsHex();
    void CopyAsBase64();
    void ExpandValue();
    void SaveNode();
    void SaveNodeValue();

private:
    QTextEdit *textEdit_;
    QTableWidget *table_;

    void GetEditView( const BIN *pBer, BerItem *pItem );
    QString GetDataView( const BIN *pData, const BerItem *pItem );
    void GetTableView( const BIN *pBer, BerItem *pItem );
    void GetTableFullView( const BIN *pBer, BerItem *pItem );

    BerItem* currentItem();
};

#endif // BER_TREE_VIEW_H
