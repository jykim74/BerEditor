/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef NUM_TRANS_DLG_H
#define NUM_TRANS_DLG_H

#include <QDialog>
#include "ui_num_trans_dlg.h"

namespace Ui {
class NumTransDlg;
}

class NumTransDlg : public QDialog, public Ui::NumTransDlg
{
    Q_OBJECT

public:
    explicit NumTransDlg(QWidget *parent = nullptr);
    ~NumTransDlg();

private slots:
    void dataTrans();
    void dataChange();

    void clickInputClear();
    void clickOutputClear();

    void clickInputHex();
    void clickInputBit();
    void clickInputDec();

private:
    void initialize();
};

#endif // NUM_TRANS_DLG_H
