#ifndef MAKE_PRI_KEY_DLG_H
#define MAKE_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_make_pri_key_dlg.h"

namespace Ui {
class MakePriKeyDlg;
}

class MakePriKeyDlg : public QDialog, public Ui::MakePriKeyDlg
{
    Q_OBJECT

public:
    explicit MakePriKeyDlg(QWidget *parent = nullptr);
    ~MakePriKeyDlg();

private:

};

#endif // MAKE_PRI_KEY_DLG_H
