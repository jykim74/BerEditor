/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAKE_BER_DLG_H
#define MAKE_BER_DLG_H

#include <QDialog>
#include "ui_make_ber_dlg.h"

namespace Ui {
class MakeBerDlg;
}

class MakeBerDlg : public QDialog, public Ui::MakeBerDlg
{
    Q_OBJECT

public:
    explicit MakeBerDlg(QWidget *parent = nullptr);
    ~MakeBerDlg();
    QString getData();

private slots:
    void runMake();
    void checkConstructed();
    void valueChanged();
    void berChanged();
    void numChanged();
    void classChanged(int index);
    void primitiveChanged(int index );
    void changeValueType( int index );
    void clickMakeValue();
    void makeHeader();

private:
    void initUI();
    void initialize();
};

#endif // MAKE_BER_DLG_H
