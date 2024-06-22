#ifndef SCEP_CLIENT_DLG_H
#define SCEP_CLIENT_DLG_H

#include <QDialog>
#include "ui_scep_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class SCEPClientDlg;
}

class SCEPClientDlg : public QDialog, public Ui::SCEPClientDlg
{
    Q_OBJECT

public:
    explicit SCEPClientDlg(QWidget *parent = nullptr);
    ~SCEPClientDlg();

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
    void savePriKeyCert( const BIN *pPriKey, const BIN *pCert );

};

#endif // SCEP_CLIENT_DLG_H
