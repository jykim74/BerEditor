#ifndef TTLV_CLIENT_DLG_H
#define TTLV_CLIENT_DLG_H

#include <QDialog>
#include "ui_ttlv_client_dlg.h"

namespace Ui {
class TTLVClientDlg;
}

class TTLVClientDlg : public QDialog, public Ui::TTLVClientDlg
{
    Q_OBJECT

public:
    explicit TTLVClientDlg(QWidget *parent = nullptr);
    ~TTLVClientDlg();

private slots:
    void findCA();
    void findCert();
    void findPriKey();
    void send();
    void viewResponse();
    void close();

private:
    void setDefaults();
};

#endif // TTLV_CLIENT_DLG_H
