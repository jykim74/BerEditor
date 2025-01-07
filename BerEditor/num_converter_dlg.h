/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef NUM_CONVERTER_DLG_H
#define NUM_CONVERTER_DLG_H

#include <QDialog>
#include "ui_num_converter_dlg.h"

namespace Ui {
class NumConverterDlg;
}

class NumConverterDlg : public QDialog, public Ui::NumConverterDlg
{
    Q_OBJECT

public:
    explicit NumConverterDlg(QWidget *parent = nullptr);
    ~NumConverterDlg();

private slots:
    void dataConversion();
    void dataChange();

    void clickInputClear();
    void clickOutputClear();

    void clickInputHex();
    void clickInputBit();
    void clickInputDec();

private:
    void initialize();
};

#endif // NUM_CONVERTER_DLG_H
