#ifndef NEW_PASSWD_DLG_H
#define NEW_PASSWD_DLG_H

#include <QDialog>
#include "ui_new_passwd_dlg.h"

namespace Ui {
class NewPasswdDlg;
}

class NewPasswdDlg : public QDialog, public Ui::NewPasswdDlg
{
    Q_OBJECT

public:
    explicit NewPasswdDlg(QWidget *parent = nullptr);
    ~NewPasswdDlg();

private slots:
    void clickOK();

private:

};

#endif // NEW_PASSWD_DLG_H
