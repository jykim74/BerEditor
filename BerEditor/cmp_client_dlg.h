#ifndef CMP_CLIENT_DLG_H
#define CMP_CLIENT_DLG_H

#include <QDialog>
#include "ui_cmp_client_dlg.h"

namespace Ui {
class CMPClientDlg;
}

class CMPClientDlg : public QDialog, public Ui::CMPClientDlg
{
    Q_OBJECT

public:
    explicit CMPClientDlg(QWidget *parent = nullptr);
    ~CMPClientDlg();

private:

};

#endif // CMP_CLIENT_DLG_H
