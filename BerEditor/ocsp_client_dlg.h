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

private slots:
    void findCert();
    void findSignCert();
    void findSignPriKey();
    void findSrvCert();

    void typeCert();
    void typeSignCert();
    void typeSignPriKey();
    void typeSrvCert();

    void viewCert();
    void viewSignCert();
    void viewSrvCert();

    void decodeCert();
    void decodeSignCert();
    void decodeSignPriKey();
    void decodeSrvCert();
    void decodeRequest();
    void decodeResponse();

    void clearRequest();
    void clearResponse();

    void clickEncode();
    void clickSend();
    void clickVerify();

    void requestChanged();
    void responseChanged();

private:
    void initialize();
};

#endif // OCSP_CLIENT_DLG_H
