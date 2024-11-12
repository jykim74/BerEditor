#ifndef KEY_ADD_DLG_H
#define KEY_ADD_DLG_H

#include <QDialog>
#include "ui_key_add_dlg.h"

namespace Ui {
class KeyAddDlg;
}

class KeyAddDlg : public QDialog, public Ui::KeyAddDlg
{
    Q_OBJECT

public:
    explicit KeyAddDlg(QWidget *parent = nullptr);
    ~KeyAddDlg();

private slots:
    void clickClearAll();
    void clickOK();

private:

};

#endif // KEY_ADD_DLG_H
