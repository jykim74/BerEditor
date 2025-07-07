#ifndef ACME_CLIENT_DLG_H
#define ACME_CLIENT_DLG_H

#include <QDialog>
#include "ui_acme_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class ACMEClientDlg;
}

static QString kCmdLocation = "Location";
static QString kCmdAccount = "Account";
static QString kCmdOrder = "Order";


static QString kCmdKeyChange = "keyChange";
static QString kCmdNewAccount = "newAccount";
static QString kCmdNewNonce = "newNonce";
static QString kCmdNewOrder = "newOrder";
static QString kCmdRenewalInfo = "renewalInfo";
static QString kCmdRevokeCert = "revokeCert";

static QString kCmdNewAuthz = "NewAuthz";
static QString kCmdFinalize = "Finalize";
static QString kCmdCertificate = "Certificate";

static QString kCmdAuthorization = "Authorization";
static QString kCmdChallenge = "Challenge";


class ACMEClientDlg : public QDialog, public Ui::ACMEClientDlg
{
    Q_OBJECT

public:
    explicit ACMEClientDlg(QWidget *parent = nullptr);
    ~ACMEClientDlg();

private slots:
    void clickGetNonce();
    void clickGetLocation();
    void clickGetDirectory();
    void clickMake();
    void clickSend();
    void clickClearURL();
    void clickClearKID();
    void clickClearRequest();
    void clickClearResponse();
    void changeRequest();
    void changeResponse();
    void clickParse();
    void changeCmd( int index );

    void clickAddDNS();
    void clickClearDNS();

private:
    void initUI();
    void initialize();

    int makeKeyExchange( QJsonObject& object );
    int makeNewAccount( QJsonObject& object );
    int makeNewNonce( QJsonObject& object );
    int makeNewOrder( QJsonObject& object );
    int makeRevokeCert( QJsonObject& object );
    int makeFinalize( QJsonObject& object );

    int parseNewOrderRsp( QJsonObject& object );;
    int parseAuthzRsp( QJsonObject& object );
    int parseOrder( QJsonObject& object );

    void addCmd( const QString strCmd, const QString strCmdURL );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );

    BIN pri_key_;
    BIN pub_key_;
};

#endif // ACME_CLIENT_DLG_H
