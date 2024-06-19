#ifndef SECP_CLIENT_DLG_H
#define SECP_CLIENT_DLG_H

#include <QDialog>
#include "ui_secp_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class SECPClientDlg;
}

class SECPClientDlg : public QDialog, public Ui::SECPClientDlg
{
    Q_OBJECT

public:
    explicit SECPClientDlg(QWidget *parent = nullptr);
    ~SECPClientDlg();

private slots:
    void clickClearURL();

    void findCACert();
    void findCert();
    void findPriKey();

    void typeCACert();
    void typeCert();
    void typePriKey();

    void viewCACert();
    void viewCert();

    void decodeCACert();
    void decodeCert();
    void decodePriKey();

    void decodeRequest();
    void decodeResponse();

    void clearRequest();
    void clearResponse();

    void requestChanged();
    void responseChanged();

    void clickClearAll();
    void clickGetCA();
    void clickMakeIssue();
    void clickMakeUpdate();
    void clickMakeGetCRL();
    void clickSend();
    void clickVerify();

private:
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );

    int getCA( BIN *pCA );
};

#endif // SECP_CLIENT_DLG_H
