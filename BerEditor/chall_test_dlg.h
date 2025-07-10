#ifndef CHALL_TEST_DLG_H
#define CHALL_TEST_DLG_H

#include <QDialog>
#include "ui_chall_test_dlg.h"

const QString kCmdHTTP01 = "HTTP-01";
const QString kCmdDNS01 = "DNS-01";
const QString kCmdTLS_ALPN01 = "TLS-ALPN-01";
const QString kCmdCLEARUP = "CLEANUP";
const QString kCmdCLEAR_TXT = "CLEAR-TXT";

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

    void clearRequest();
    void clearResponse();

    void changeRequest();
    void changeResponse();
    void clickRequestView();
    void clickResponseView();

private:
    void initUI();

    int makeHTTP01();
    int makeDNS01();
    int makeTLS_ALPN01();
    int makeCLEANUP();
    int makeCLEAR_TXT();
};

#endif // CHALL_TEST_DLG_H
