/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QPainter>
#include <QApplication>
#include <QPixmap>

#include "ber_item_delegate.h"
#include "ber_item.h"
#include "ber_model.h"

BerItemDelegate::BerItemDelegate( QObject *parent )
    : QStyledItemDelegate (parent)
{

}

BerItemDelegate::~BerItemDelegate()
{

}

void BerItemDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyledItemDelegate::paint(painter, option, index );
}

QSize BerItemDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    return QStyledItemDelegate::sizeHint(option, index);

    /*
    int width = 200;
    int height = 40;

    return QSize( width, height );
    */
}


BerItem* BerItemDelegate::getItem(const QModelIndex &index) const
{
    BerModel *tree_model = (BerModel *)index.model();

    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    return item;
}

