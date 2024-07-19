/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DATA_ENCODER_DLG_H
#define DATA_ENCODER_DLG_H

#include <QDialog>
#include "ui_data_encoder_dlg.h"
#include "js_bin.h"

namespace Ui {
class DataEncoderDlg;
}



class DataEncoderDlg : public QDialog, public Ui::DataEncoderDlg
{
    Q_OBJECT

public:
    explicit DataEncoderDlg(QWidget *parent = nullptr);
    ~DataEncoderDlg();

private slots:
    void clickFindFile();
    void onClickEncodeBtn();
    void outTypeChanged( int index );
    void inputChanged();
    void outputChanged();
    void clickChange();

    void clickInputClear();
    void clickOutputClear();

private:
    void makeDump( const BIN *pData );
    void initialize();
//    Ui::DataEncoderDlg *ui;
};

#endif // DATA_ENCODER_DLG_H
