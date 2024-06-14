#ifndef SECP_CLIENT_DLG_H
#define SECP_CLIENT_DLG_H

#include <QDialog>
#include "ui_secp_client_dlg.h"

namespace Ui {
class SECPClientDlg;
}

class SECPClientDlg : public QDialog, public Ui::SECPClientDlg
{
    Q_OBJECT

public:
    explicit SECPClientDlg(QWidget *parent = nullptr);
    ~SECPClientDlg();

private:
    void initialize();
};

#endif // SECP_CLIENT_DLG_H
