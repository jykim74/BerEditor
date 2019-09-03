#ifndef BER_TREE_VIEW_H
#define BER_TREE_VIEW_H

#include <QTreeView>
#include <QTextBrowser>
#include "js_bin.h"

class BerItem;

class BerTreeView : public QTreeView
{
    Q_OBJECT
public:
    BerTreeView( QWidget* parent = 0 );
    void setTextEdit( QTextEdit *txtEdit_ );

private slots:
    void onItemClicked( const QModelIndex& index );

private:
    QTextEdit *textEdit_;

    QString GetEditView( const BIN *pBer, BerItem *pItem );
    QString GetDataView( const BIN *pData, const BerItem *pItem );
};

#endif // BER_TREE_VIEW_H
