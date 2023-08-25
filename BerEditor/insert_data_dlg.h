#ifndef INSERT_DATA_DLG_H
#define INSERT_DATA_DLG_H

#include <QDialog>
#include "ui_insert_data_dlg.h"

namespace Ui {
class InsertDataDlg;
}

class InsertDataDlg : public QDialog, public Ui::InsertDataDlg
{
    Q_OBJECT

public:
    explicit InsertDataDlg(QWidget *parent = nullptr);
    ~InsertDataDlg();

    QString getTextData();

private slots :
    void viewData();
    void dataChanged();

private:
};

#endif // INSERT_DATA_DLG_H
