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
    void clickClearURL();

    void inputChanged();
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

    void findCACert();
    void viewCACert();
    void decodeCACert();
    void typeCACert();

    void clickEncode();
    void clickSend();
    void clickVerify();
    void clickVerifySigned();

    void clickTSTInfo();
    void clickViewCMS();
private:
    void initUI();
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // TSP_CLIENT_DLG_H
