#ifndef TSP_CLIENT_DLG_H
#define TSP_CLIENT_DLG_H

#include <QDialog>
#include "ui_tsp_client_dlg.h"

namespace Ui {
class TSPClientDlg;
}

class TSPClientDlg : public QDialog, public Ui::TSPClientDlg
{
    Q_OBJECT

public:
    explicit TSPClientDlg(QWidget *parent = nullptr);
    ~TSPClientDlg();

private slots:
    void requestChanged();
    void responseChanged();

    void decodeRequest();
    void decodeResponse();

    void clearRequest();
    void clearResponse();

    void findSrvCert();
    void viewSrvCert();
    void decodeSrvCert();
    void typeSrvCert();

    void clickEncode();
    void clickSend();
    void clickVerify();

private:
    void initialize();
};

#endif // TSP_CLIENT_DLG_H
