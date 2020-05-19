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
    virtual void accept();
    void dataTrans();
    void dataChange();

private:

};

#endif // NUM_TRANS_DLG_H
