/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    void viewCurrent();

    QString GetTextView();
/*
    void showTextView();
    void showXMLView();
*/

private slots:
    void onItemClicked( const QModelIndex& index );
    void ShowContextMenu( QPoint point );
    void ExpandValue();

public slots:
    void CopyAsHex();
    void CopyAsBase64();
    void copy();

    void SaveNode();
    void SaveNodeValue();
    void EditValue();
    void InsertBER();

    void treeExpandAll();
    void treeExpandNode();
    void treeCollapseAll();
    void treeCollapseNode();
    void treeExpandItem( int nRow, int nCol );

private:
    void GetTableView( const BIN *pBer, BerItem *pItem );
    void GetTableFullView( const BIN *pBer, BerItem *pItem );

    void infoItem( BerItem *pItem, int nWidth );
    BerItem* currentItem();

    void showItemText( BerItem* item, BerItem* setItem = nullptr, bool bBold = false );
    void showItemXML( BerItem* item, BerItem* setItem = nullptr, bool bBold = false );

    void showText( int level, const QString& strMsg, QColor cr = QColor(0x00, 0x00, 0x00), bool bBold = false );
    void showXML( int level, const QString& strMsg, QColor cr = QColor(0x00, 0x00, 0x00), bool bBold = false );
};

#endif // BER_TREE_VIEW_H
