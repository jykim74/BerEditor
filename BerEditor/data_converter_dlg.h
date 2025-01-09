/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef DATA_CONVERTER_DLG_H
#define DATA_CONVERTER_DLG_H

#include <QDialog>
#include "ui_data_converter_dlg.h"
#include "js_bin.h"

namespace Ui {
class DataConverterDlg;
}



class DataConverterDlg : public QDialog, public Ui::DataConverterDlg
{
    Q_OBJECT

public:
    explicit DataConverterDlg(QWidget *parent = nullptr);
    ~DataConverterDlg();

private slots:
    void clickFindFile();
    void onClickConvertBtn();
    void outTypeChanged( int index );
    void inputChanged();
    void outputChanged();
    void clickChange();

    void clickInputClear();
    void clickOutputClear();

private:
    void makeDump( const BIN *pData );
    void initialize();
};

#endif // DATA_CONVERTER_DLG_H
