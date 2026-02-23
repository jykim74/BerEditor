#ifndef COMPMODEL_H
#define COMPMODEL_H

#include <QStandardItemModel>
#include "ber_item.h"
#include "comp_tree.h"
#include "js_bin.h"

class CompModel : public QStandardItemModel
{
    Q_OBJECT
public:
    CompModel(QObject *parent = 0);
    ~CompModel();

    CompTree* getTreeView() { return tree_view_; };
    void setBER( const BIN *pBER );
    const BIN& getBER() { return binBER_; };

    int getItemInfo( const BIN *pBER, int nOffset, BerItem *pItem );
    int getItemInfo( int nOffset, BerItem *pItem );
    int getConstructedItemInfo( const BIN *pBER, BerItem *pItem, bool bSETSort, bool bExpand );
    int makeTree( bool bSETSort, bool bExpand );

    BerItem* getCurrentItem();
    void getCurrentValue( BIN *pValue );
    void getValue( BerItem *item, BIN *pValue );
    void setSelectItem( const BerItem *pItem );

    const QStringList getPositon( BerItem *pItem );
    BerItem* findItemByPostion( const QStringList listPos );

    BerItem* getNext( BerItem *pItem );
    BerItem* getPrev( BerItem *pItem );
    void setItemColor( BerItem *pItem, QColor cr );
    void setAllColor( QColor cr );
    void clearView();

public slots:

private:
    int IsPrev( BerItem *pA, BerItem *pB );

    BIN binBER_;
    CompTree* tree_view_;
};

#endif // COMPMODEL_H
