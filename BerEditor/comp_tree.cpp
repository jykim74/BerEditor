#include <QFile>
#include <QStandardItemModel>
#include <QTreeView>

#include "comp_tree.h"
#include "comp_model.h"
#include "ber_compare_dlg.h"

CompTree::CompTree( QWidget* parent )
{
    QFile qss(":/comptree.qss");
    qss.open( QFile::ReadOnly );
    setStyleSheet(qss.readAll());
    qss.close();
}

CompTree::~CompTree()
{

}

BerItem* CompTree::getNext( BerItem *pItem )
{
    const BerItem *pParentItem = nullptr;
    const BerItem *pCurItem = nullptr;
    CompModel *tree_model = (CompModel *)model();

    QModelIndex idx;
    int nCurRow = 0;

    if( pItem == NULL )
        return (BerItem *)tree_model->item(0,0);

    pCurItem = pItem;
    if( pCurItem->hasChildren() == true )
    {
        return (BerItem *)pCurItem->child(0);
    }

    nCurRow = pCurItem->row();

    pParentItem = (BerItem *)pCurItem->parent();
    if( pParentItem == NULL ) return nullptr;

    if( pParentItem->rowCount() > (nCurRow + 1) )
        return (BerItem *)pParentItem->child( nCurRow + 1 );

    nCurRow = pParentItem->row();
    pCurItem = pParentItem;


    while( pCurItem )
    {
        pParentItem = (BerItem *)pCurItem->parent();
        if( pParentItem == nullptr ) return nullptr;

        if( pParentItem->rowCount() > (nCurRow + 1 ) )
            return (BerItem *)pParentItem->child( nCurRow + 1 );

        nCurRow = pParentItem->row();
        pCurItem = pParentItem;
    }

    return nullptr;
}

BerItem* CompTree::getPrev( BerItem *pItem )
{
    BerItem *pChildItem = nullptr;
    BerItem *pCurItem = nullptr;

    CompModel *tree_model = (CompModel *)model();

    QModelIndex idx;
    int nCurRow = 0;

    if( pItem == NULL )
        return (BerItem *)tree_model->item(0,0);

    pCurItem = pItem;

    BerItem *pParent = (BerItem *)pCurItem->parent();
    if( pParent == NULL ) return nullptr;

    nCurRow = pCurItem->row();
    if( nCurRow <= 0 ) return pParent;

    pCurItem = (BerItem *)pParent->child( nCurRow - 1 );
    while( pCurItem )
    {
        if( pCurItem->hasChildren() == false ) return pCurItem;

        nCurRow = pCurItem->rowCount();
        pChildItem = (BerItem *)pCurItem->child( nCurRow - 1 );

        pCurItem = pChildItem;
    }

    return nullptr;
}

void CompTree::setItemColor( BerItem *pItem, QColor cr )
{
    if( pItem == nullptr ) return;
    pItem->setData(QBrush(cr), Qt::ForegroundRole );
}
