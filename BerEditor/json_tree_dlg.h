#ifndef ACME_TREE_DLG_H
#define ACME_TREE_DLG_H

#include <QDialog>
#include <QJsonObject>
#include "ui_json_tree_dlg.h"

namespace Ui {
class JSONTreeDlg;
}

class JSONTreeDlg : public QDialog, public Ui::JSONTreeDlg
{
    Q_OBJECT

public:
    explicit JSONTreeDlg(QWidget *parent = nullptr);
    explicit JSONTreeDlg(QWidget *parent, bool bDecode );
    ~JSONTreeDlg();

    void setJson( const QString strJson );

private slots:
    void clickTreeItem( QTreeWidgetItem* item, int index );
    void slotTreeMenuRequested( QPoint pos );
    void decodeTreeMenu();
    void clickClear();

private:
    QJsonObject json_;
    void initUI();

    void setObject( QTreeWidgetItem* pParentItem, QJsonObject& object );
    void setArray( QTreeWidgetItem* pParentItem, QJsonArray& array );
};

#endif // ACME_TREE_DLG_H
