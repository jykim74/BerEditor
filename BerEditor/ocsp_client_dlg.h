#ifndef OCSP_CLIENT_DLG_H
#define OCSP_CLIENT_DLG_H

#include <QDialog>
#include "ui_ocsp_client_dlg.h"
#include "js_bin.h"

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
    void checkUseSign();
    void clickClearURL();

    void clickClearOCSP();
    void clickSetURL();
    void clickSetCACert();

    void findCACert();
    void findCert();
    void findSignCert();
    void findSignPriKey();
    void findSrvCert();

    void typeCACert();
    void typeCert();
    void typeSignCert();
    void typeSignPriKey();
    void typeSrvCert();

    void viewCACert();
    void viewCert();
    void viewSignCert();
    void viewSrvCert();

    void decodeCACert();
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

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );
};

#endif // OCSP_CLIENT_DLG_H
