/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef EDIT_VALUE_DLG_H
#define EDIT_VALUE_DLG_H

#include <QDialog>
#include "ui_edit_value_dlg.h"

class BerItem;

namespace Ui {
class EditValueDlg;
}

class EditValueDlg : public QDialog, public Ui::EditValueDlg
{
    Q_OBJECT

public:
    explicit EditValueDlg(QWidget *parent = nullptr);
    ~EditValueDlg();

    void setItem( BerItem *pItem );
    QString getData();
    void setHeadLabel( const QString strHead );

private slots:
    void runChange();
    void runDelete();
    void runAdd();
    void changeValueText();
    void changeBER();
    void changeValueType(int index);

    void clickMakeValue();

private:
    void initialize();
    BerItem *ber_item_;
    void makeHeader();
};

#endif // EDIT_VALUE_DLG_H
