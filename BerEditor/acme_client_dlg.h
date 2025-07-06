#ifndef ACME_CLIENT_DLG_H
#define ACME_CLIENT_DLG_H

#include <QDialog>
#include "ui_acme_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class ACMEClientDlg;
}

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
static QString kCmdOrder = "Order";

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
    void clickClearRequest();
    void clickClearResponse();
    void changeRequest();
    void changeResponse();
    void clickParse();
    void changeCmd( int index );

private:
    void initUI();
    void initialize();

    int makeKeyExchange( QJsonObject& object );
    int makeNewAccount( QJsonObject& object );
    int makeNewNonce( QJsonObject& object );
    int makeNewOrder( QJsonObject& object );
    int makeRenewalInfo( QJsonObject& object );
    int makeRevokeCert( QJsonObject& object );
    int makeFinalize( QJsonObject& object, const BIN *pPri );

    int parseNewOrderRsp( QJsonObject& object );;

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // ACME_CLIENT_DLG_H
