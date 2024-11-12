#ifndef KEY_LIST_DLG_H
#define KEY_LIST_DLG_H

#include <QDialog>
#include "ui_key_list_dlg.h"

namespace Ui {
class KeyListDlg;
}

class KeyListDlg : public QDialog, public Ui::KeyListDlg
{
    Q_OBJECT

public:
    explicit KeyListDlg(QWidget *parent = nullptr);
    ~KeyListDlg();

private slots:
    void clickKeyAdd();
    void clickKeyDel();
    void clickKeyView();

private:
    void initialize();
};

#endif // KEY_LIST_DLG_H
