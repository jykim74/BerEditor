#ifndef TTLV_CLIENT_DLG_H
#define TTLV_CLIENT_DLG_H

#include <QDialog>
#include "ui_ttlv_client_dlg.h"
#include "js_bin.h"

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
    void clickSend();
    void close();
    void changeResponse();
    void changeRequest();

    void checkEncPriKey();
    void clickClearURL();

    void typeCACert();
    void typeCert();
    void typePriKey();

    void viewCACert();
    void viewCert();
    void viewPriKey();

    void decodeCACert();
    void decodeCert();
    void decodePriKey();


    void decodeRequest();
    void decodeResponse();

    void clearRequest();
    void clearResponse();

private:
    void initialize();
    int readPrivateKey( BIN *pPriKey );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // TTLV_CLIENT_DLG_H
