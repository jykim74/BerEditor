#ifndef ACME_CLIENT_DLG_H
#define ACME_CLIENT_DLG_H

#include <QDialog>
#include "ui_acme_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class ACMEClientDlg;
}

#if 0
static QString kCmdLocation = "Location";
static QString kCmdAccount = "Account";
static QString kCmdOrder = "Order";
static QString kCmdOrders = "Orders";

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
#else
static QString kCmdLocation = "LOCATION";
static QString kCmdAccount = "ACCOUNT";
static QString kCmdOrder = "ORDER";
static QString kCmdOrders = "ORDERS";

static QString kCmdKeyChange = "KEYCHANGE";
static QString kCmdNewAccount = "NEWACCOUNT";
static QString kCmdNewNonce = "NEWNONCE";
static QString kCmdNewOrder = "NEWORDER";
static QString kCmdRenewalInfo = "RENEWALINFO";
static QString kCmdRevokeCert = "REVOKECERT";

static QString kCmdNewAuthz = "NEWAUTHZ";
static QString kCmdFinalize = "FINALIZE";
static QString kCmdCertificate = "CERTIFICATE";

static QString kCmdAuthorization = "AUTHORIZATION";
static QString kCmdChallenge = "CHALLENGE";

static QString kCmdDeactivate = "DEACTIVATE";
static QString kCmdUpdateAccount = "UPDATEACCOUNT";
#endif


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
    void clickChallTest();

    void clickClearURL();
    void clickClearKID();
    void clickClearRequest();
    void clickClearResponse();
    void changeRequest();
    void changeResponse();

    void changeCmd( int index );

    int clickMake();
    int clickDeactivate();
    int clickUpdateAccount();

    int clickParse();
    int clickSend();

    void clickAddDNS();
    void clickClearDNS();
    void clickClearAll();

    void clickVerify();
    void clickRequestView();
    void clickResponseView();

    void clickIssueCert();
    void clickTest();

private:
    void initUI();
    void initialize();

    int makeKeyExchange( QJsonObject& object );
    int makeNewAccount( QJsonObject& object );
    int makeNewNonce( QJsonObject& object );
    int makeNewOrder( QJsonObject& object );
    int makeRevokeCert( QJsonObject& object );
    int makeFinalize( QJsonObject& object );
    int makeRenewalInfo( QJsonObject& object );
    int makeDeactivate( QJsonObject& object );
    int makeUpadateAccount( QJsonObject& object );

    int parseNewAccountRsp( QJsonObject& object );
    int parseNewOrderRsp( QJsonObject& object );;
    int parseAuthzRsp( QJsonObject& object );
    int parseAccountRsp( QJsonObject& object );
    int parseCertificateRsp( const QString strChain );
    int parseOrdersRsp( QJsonObject& object );

    void addCmd( const QString strCmd, const QString strCmdURL );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int savePriKeyCert( const BIN *pPriKey, const BIN *pCert );

    void resetKey();

    BIN pri_key_;
    BIN pub_key_;
    BIN csr_pri_key_;
    QString key_name_;
};

#endif // ACME_CLIENT_DLG_H
