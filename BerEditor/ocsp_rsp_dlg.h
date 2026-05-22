#ifndef OCSP_RSP_DLG_H
#define OCSP_RSP_DLG_H

#include <QDialog>
#include "ui_ocsp_rsp_dlg.h"
#include "js_bin.h"

namespace Ui {
class OCSPRspDlg;
}

class OCSPRspDlg : public QDialog, public Ui::OCSPRspDlg
{
    Q_OBJECT

public:
    explicit OCSPRspDlg(QWidget *parent = nullptr);
    ~OCSPRspDlg();

    void setResponse( const BIN *pResp );

private slots:
    void clickViewSigner();
    void clickDecode();

    void clickInfoTable();
    void clickRspTree();

private:
    void initUI();
    void initialize();

    BIN rsp_;
    BIN signer_;
};

#endif // OCSP_RSP_DLG_H
