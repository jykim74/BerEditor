#ifndef ACME_CLIENT_DLG_H
#define ACME_CLIENT_DLG_H

#include <QDialog>
#include "ui_acme_client_dlg.h"

namespace Ui {
class ACMEClientDlg;
}

static QString kCmdKeyChange = "keyChange";
static QString kCmdNewAccount = "newAccount";
static QString kCmdNewNonce = "newNonce";
static QString kCmdNewOrder = "newOrder";
static QString kCmdRenewalInfo = "renewalInfo";
static QString kCmdRevokeCert = "revokeCert";

class ACMEClientDlg : public QDialog, public Ui::ACMEClientDlg
{
    Q_OBJECT

public:
    explicit ACMEClientDlg(QWidget *parent = nullptr);
    ~ACMEClientDlg();

private slots:
    void clickGetNonce();
    void clickGetDirectory();
    void clickMake();
    void clickSend();
    void clickClearURL();
    void clickClearRequest();
    void clickClearResponse();
    void changeRequest();
    void changeResponse();
    void clickParse();
    void changeCmd( int index );

private:
    void initUI();
    void initialize();

    QString makeKeyExchange();
    QString makeNewAccount();
    QString makeNewNonce();
    QString makeNewOrder();
    QString makeRenewalInfo();
    QString makeRevokeCert();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // ACME_CLIENT_DLG_H
