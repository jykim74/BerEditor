#ifndef TLS_VERIFY_DLG_H
#define TLS_VERIFY_DLG_H

#include <QDialog>
#include "ui_tls_verify_dlg.h"


namespace Ui {
class TLSVerifyDlg;
}

class TLSVerifyDlg : public QDialog, public Ui::TLSVerifyDlg
{
    Q_OBJECT

public:
    explicit TLSVerifyDlg(QWidget *parent = nullptr);
    ~TLSVerifyDlg();

private slots:
    void clickConnect();
    void clickRefresh();

private:
    void initialize();
    int verifyURL( const QString strHost, int nPort );
};

#endif // TLS_VERIFY_DLG_H
