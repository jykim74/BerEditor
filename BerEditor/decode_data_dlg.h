/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DECODE_DATA_DLG_H
#define DECODE_DATA_DLG_H

#include <QDialog>
#include "ui_decode_data_dlg.h"

namespace Ui {
class DecodeDataDlg;
}

class DecodeDataDlg : public QDialog, public Ui::DecodeDataDlg
{
    Q_OBJECT

public:
    explicit DecodeDataDlg(QWidget *parent = nullptr);
    ~DecodeDataDlg();

    QString getTextData();

private slots :
    void decodeData();
    void dataChanged();
    void clearData();
    void findData();

private:
    void initUI();
};

#endif // DECODE_DATA_DLG_H
