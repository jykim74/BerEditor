#ifndef AUTH_REF_DLG_H
#define AUTH_REF_DLG_H

#include <QDialog>
#include "ui_auth_ref_dlg.h"

namespace Ui {
class AuthRefDlg;
}

class AuthRefDlg : public QDialog, public Ui::AuthRefDlg
{
    Q_OBJECT

public:
    explicit AuthRefDlg(QWidget *parent = nullptr);
    ~AuthRefDlg();

private slots:
    void clickOK();

private:
    void initialize();
};

#endif // AUTH_REF_DLG_H
