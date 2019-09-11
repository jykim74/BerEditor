#ifndef GEN_HASH_DLG_H
#define GEN_HASH_DLG_H

#include <QDialog>
#include "ui_gen_hash_dlg.h"

namespace Ui {
class GenHashDlg;
}

class GenHashDlg : public QDialog, public Ui::GenHashDlg
{
    Q_OBJECT

public:
    GenHashDlg(QWidget *parent = nullptr);
    ~GenHashDlg();

private slots:
    virtual void accept();

private:
//    Ui::GenHashDlg *ui;
};

#endif // GEN_HASH_DLG_H
