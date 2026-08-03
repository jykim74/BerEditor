#ifndef DNS_CHECK_DLG_H
#define DNS_CHECK_DLG_H

#include <QDialog>
#include "ui_dns_check_dlg.h"

#include "js_bin.h"

namespace Ui {
class DNSCheckDlg;
}

enum ACME_CheckType {
    ACME_HTTP_01 = 0,
    ACME_DNS_01,
    ACME_TLS_ALPN_01
};

class DNSCheckDlg : public QDialog, public Ui::DNSCheckDlg
{
    Q_OBJECT

public:
    explicit DNSCheckDlg(QWidget *parent = nullptr);
    ~DNSCheckDlg();

    void addDNS( const QString strDNS );
    void setPubKey( const BIN *pPubKey );
    void setToken( const QString strToken );

private slots:
    void clickHTTP01();
    void clickDNS01();
    void clickTLS_ALPN01();
    void clickMakeSelfSignCert();

private:
    void initUI();
    void initialize();

    int checkHTTP01( const QString strDNS, const QString strToken, const BIN *pPub );
    int checkDNS01( const QString strDNS, const QString strToken, const BIN *pPub );
    int checkTLS_ALPN01( const QString strDNS, const QString strToken, const BIN *pPub );
    void checkDNS( ACME_CheckType type );

    BIN pub_key_;
};

#endif // DNS_CHECK_DLG_H
