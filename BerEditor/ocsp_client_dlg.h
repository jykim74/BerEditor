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
    void setURI( const QString strURL );
    void setCA( const QString strURL );
    void setCert( const QString strDN, const BIN *pCert );

private slots:
    void checkUseSign();
    void checkUseNonce();
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
    void viewSignPriKey();
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
    void clickViewCertID();
    void clickVerify();

    void nonceChanged();
    void requestChanged();
    void responseChanged();

    void checkEncPriKey();
private:
    void initUI();
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );

    BIN cert_;
};

#endif // OCSP_CLIENT_DLG_H
