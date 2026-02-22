#ifndef COMPTREE_H
#define COMPTREE_H

#include <QTreeView>
#include <QTableWidget>
#include "js_bin.h"
#include "ber_item.h"

class CompTree : public QTreeView
{
    Q_OBJECT
public:
    CompTree( QWidget* parent = 0);
    ~CompTree();

    BerItem* getNext( BerItem *pItem );
    BerItem* getPrev( BerItem *pItem );

public slots:

private:
};

#endif // COMPTREE_H
