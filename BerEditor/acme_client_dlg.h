#ifndef ACME_CLIENT_DLG_H
#define ACME_CLIENT_DLG_H

#include <QDialog>
#include "ui_acme_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class ACMEClientDlg;
}

static QString kCmdDirectory = "DIRECTORY";
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


class ACMEClientDlg : public QDialog, public Ui::ACMEClientDlg
{
    Q_OBJECT

public:
    explicit ACMEClientDlg(QWidget *parent = nullptr);
    ~ACMEClientDlg();

private slots:
    void slotCmdTableMenuRequested( QPoint pos );
    void deleteCmd();
    void remakeCmd();

    void clickGetNonce();
    void clickGetLocation();
    void clickGetDirectory();
    void clickChallTest();

    void clickClearCmd();
    void clickClearAuth();
    void clickClearChall();
    void clickClearOrder();

    void clickClearURL();
    void clickKIDGetPubKey();
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

    int parseGetDirectory( QJsonObject& object );
    int parseNewAccountRsp( QJsonObject& object );
    int parseNewOrderRsp( QJsonObject& object );;
    int parseAuthzRsp( QJsonObject& object );
    int parseAccountRsp( QJsonObject& object );
    int parseCertificateRsp( const QString strChain );
    int parseOrdersRsp( QJsonObject& object );
    int parseOrderRsp( QJsonObject& object );
    int parseLocationRsp( QJsonObject& object );

    int addCmd( const QString strCmd, const QString strCmdURL );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int savePriKeyCert( const BIN *pPriKey, const BIN *pCert );

    void resetKey();
    bool isCmd( const QString strName );
    int makeCmd( const QString strCmd, const QString strURL );
    int runCmd( const QString strCmd );

    BIN pri_key_;
    BIN pub_key_;
    BIN csr_pri_key_;
    BIN kid_pub_key_;
    QString key_name_;
};

#endif // ACME_CLIENT_DLG_H
