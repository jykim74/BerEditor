#ifndef INSERT_DATA_DLG_H
#define INSERT_DATA_DLG_H

#include <QDialog>

namespace Ui {
class InsertDataDlg;
}

class InsertDataDlg : public QDialog
{
    Q_OBJECT

public:
    explicit InsertDataDlg(QWidget *parent = nullptr);
    ~InsertDataDlg();

private:
    Ui::InsertDataDlg *ui;
};

#endif // INSERT_DATA_DLG_H
