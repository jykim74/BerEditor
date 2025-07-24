#ifndef CHALL_TEST_DLG_H
#define CHALL_TEST_DLG_H

#include <QDialog>
#include "ui_chall_test_dlg.h"

const QString kCmdHTTP01 = "HTTP-01";
const QString kCmdDNS01 = "DNS-01";
const QString kCmdTLS_ALPN01 = "TLS-ALPN-01";
const QString kCmdCLEARUP = "CLEANUP";
const QString kCmdCLEAR_TXT = "CLEAR-TXT";

const QString kManSetDefaultIPV4 = "SetDefaultIPV4";
const QString kManSetDefaultIPV6 = "SetDefaultIPV6";
const QString kManAddA = "AddA";
const QString kManClearA = "ClearA";
const QString kManAddAAAA = "AddAAAA";
const QString kManClearAAAA = "ClearAAAA";
const QString kManAddCAA = "AddCAA";
const QString kManClearCAA = "ClearCAA";
const QString kManSetCName = "SetCName";
const QString kManClearCName = "ClearCName";
const QString kManServerFail = "ServerFail";
const QString kManAddHTTP01 = "AddHTTP01";
const QString kManDelHTTP01 = "DelHTTP01";
const QString kManAddRedirect = "AddRedirect";
const QString kManDelRedirect = "DelRedirect";
const QString kManSetTxt = "SetTxt";
const QString kManClearTxt = "ClearTxt";
const QString kManAddTLS_ALPN01 = "AddTLS_ALPN01";
const QString kManDelTLS_ALPN01 = "DelTLS_ALPN01";
const QString kManHTTPRequestHistory = "HTTPRequestHistory";
const QString kManDNSRequestHistory = "DNSRequestHistory";
const QString kManClearRequestHistory = "ClearRequestHistory";

const QString kManSetDefaultIPV4Path = "/set-default-ipv4";
const QString kManSetDefaultIPV6Path = "/set-default-ipv6";
const QString kManAddAPath = "/add-a";
const QString kManClearAPath = "/clear-a";
const QString kManAddAAAAPath = "/add-aaaa";
const QString kManClearAAAAPath = "/clear-aaaa";
const QString kManAddCAAPath = "/add-caa";
const QString kManClearCAAPath = "/clear-caa";
const QString kManSetCNamePath = "/set-cname";
const QString kManClearCNamePath = "/clear-cname";
const QString kManServerFailPath = "/set-servfail";
const QString kManAddHTTP01Path = "/add-http01";
const QString kManDelHTTP01Path = "/del-http01";
const QString kManAddRedirectPath = "/add-redirect";
const QString kManDelRedirectPath = "/del-redirect";
const QString kManSetTxtPath = "/set-txt";
const QString kManClearTxtPath = "/clear-txt";
const QString kManAddTLS_ALPN01Path = "/add-tlsalpn01";
const QString kManDelTLS_ALPN01Path = "/del-tlsalpn01";
const QString kManHTTPRequestHistoryPath = "/http-request-history";
const QString kManDNSRequestHistoryPath = "/dns-request-history";
const QString kManClearRequestHistoryPath = "/clear-request-history";


namespace Ui {
class ChallTestDlg;
}

class ChallTestDlg : public QDialog, public Ui::ChallTestDlg
{
    Q_OBJECT

public:
    explicit ChallTestDlg(QWidget *parent = nullptr);
    ~ChallTestDlg();

private slots:
    void changeCmdType( int index );
    int clickMake();
    int clickSend();

    void clickValueList();
    void clickValueClear();

    void clearRequest();
    void clearResponse();

    void changeRequest();
    void changeResponse();
    void clickRequestView();
    void clickResponseView();

private:
    void initUI();

    int makeRequest();

    void setHost( const QString strLabel, bool bEnable = true );
    void setValue( const QString strLabel, bool bEnable = true );

    void setEnvServer( const QString strServer );
    void setEnvPort( int nPort );
    const QString getEnvServer();
    int getEnvPort();
};

#endif // CHALL_TEST_DLG_H
