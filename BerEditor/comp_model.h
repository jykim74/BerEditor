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

public slots:

private:

    BIN binBER_;
    CompTree* tree_view_;
};

#endif // COMPMODEL_H
