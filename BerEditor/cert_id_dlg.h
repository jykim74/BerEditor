#ifndef CERT_ID_DLG_H
#define CERT_ID_DLG_H

#include <QDialog>
#include "ui_cert_id_dlg.h"
#include "js_bin.h"

namespace Ui {
class CertIDDlg;
}

class CertIDDlg : public QDialog, public Ui::CertIDDlg
{
    Q_OBJECT

public:
    explicit CertIDDlg(QWidget *parent = nullptr);
    ~CertIDDlg();

    void setResponse( const BIN *pResp );
    void setResponse2( const BIN *pResp );

private slots:
    void clickViewSigner();
    void clickDecode();

private:
    void initUI();
    void initialize();

    BIN resp_;
    BIN signer_;
};

#endif // CERT_ID_DLG_H
