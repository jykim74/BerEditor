#ifndef CMP_CLIENT_DLG_H
#define CMP_CLIENT_DLG_H

#include <QDialog>
#include "ui_cmp_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class CMPClientDlg;
}

class CMPClientDlg : public QDialog, public Ui::CMPClientDlg
{
    Q_OBJECT

public:
    explicit CMPClientDlg(QWidget *parent = nullptr);
    ~CMPClientDlg();

private slots:
    void clickGENM();
    void clickIR();
    void clickKUR();
    void clickRR();
    void clickClearAll();

    void findCACert();
    void viewCACert();
    void decodeCACert();
    void typeCACert();

    void findCert();
    void viewCert();
    void decodeCert();
    void typeCert();

    void findPriKey();
    void decodePriKey();
    void typePriKey();

    void clearRequest();
    void decodeRequest();

    void clearResponse();
    void decodeResponse();

private:
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );
};

#endif // CMP_CLIENT_DLG_H
