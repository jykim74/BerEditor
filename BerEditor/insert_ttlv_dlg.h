#ifndef INSERT_TTLV_DLG_H
#define INSERT_TTLV_DLG_H

#include <QDialog>
#include "ui_insert_ttlv_dlg.h"

namespace Ui {
class InsertTTLVDlg;
}

class InsertTTLVDlg : public QDialog, public Ui::InsertTTLVDlg
{
    Q_OBJECT

public:
    explicit InsertTTLVDlg(QWidget *parent = nullptr);
    ~InsertTTLVDlg();

private slots:
    void clickView();
    void changeData();

private:
    void initialize();
};

#endif // INSERT_TTLV_DLG_H
