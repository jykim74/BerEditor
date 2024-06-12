#ifndef OCSP_CLIENT_DLG_H
#define OCSP_CLIENT_DLG_H

#include <QDialog>
#include "ui_ocsp_client_dlg.h"

namespace Ui {
class OCSPClientDlg;
}

class OCSPClientDlg : public QDialog, public Ui::OCSPClientDlg
{
    Q_OBJECT

public:
    explicit OCSPClientDlg(QWidget *parent = nullptr);
    ~OCSPClientDlg();

private:

};

#endif // OCSP_CLIENT_DLG_H
