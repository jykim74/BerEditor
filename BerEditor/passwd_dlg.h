#ifndef PASSWD_DLG_H
#define PASSWD_DLG_H

#include <QDialog>
#include "ui_passwd_dlg.h"

namespace Ui {
class PasswdDlg;
}

class PasswdDlg : public QDialog, public Ui::PasswdDlg
{
    Q_OBJECT

public:
    explicit PasswdDlg(QWidget *parent = nullptr);
    ~PasswdDlg();

private slots:
    void clickOK();

private:

};

#endif // PASSWD_DLG_H
