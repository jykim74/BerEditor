#include <QTreeView>
#include <QHeaderView>

#include "comp_model.h"

CompModel::CompModel(QObject *parent)
{
    memset( &binBER_, 0x00, sizeof(BIN));

    tree_view_ = new CompTree;
    tree_view_->setModel( this );

    tree_view_->header()->setVisible( false );
}

CompModel::~CompModel()
{
    if( tree_view_ ) delete tree_view_;
    JS_BIN_reset( &binBER_ );
}
