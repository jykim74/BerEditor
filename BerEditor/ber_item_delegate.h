/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef BER_ITEM_DELEGATE_H
#define BER_ITEM_DELEGATE_H

#include <QTableView>
#include <QStandardItem>
#include <QStyledItemDelegate>
#include <QModelIndex>

class BerItem;


class BerItemDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit BerItemDelegate(QObject *parent=0);
    virtual ~BerItemDelegate();

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index ) const;
    QSize sizeHint( const QStyleOptionViewItem& option, const QModelIndex& index ) const;

private:
    BerItem* getItem(const QModelIndex &index ) const;
};


#endif // BER_ITEM_DELEGATE_H
