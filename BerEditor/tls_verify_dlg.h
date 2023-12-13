#ifndef TLS_VERIFY_DLG_H
#define TLS_VERIFY_DLG_H

#include <QDialog>
#include "ui_tls_verify_dlg.h"
#include "js_bin.h"


namespace Ui {
class TLSVerifyDlg;
}

class TLSVerifyDlg : public QDialog, public Ui::TLSVerifyDlg
{
    Q_OBJECT

public:
    explicit TLSVerifyDlg(QWidget *parent = nullptr);
    ~TLSVerifyDlg();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

private slots:
    void clickConnect();
    void clickRefresh();
    void clickClearURL();
    void clickClearSaveURL();
    void clickClearResult();

    void findTrustFolder();
    void findTrustCACert();
    void clickLoadTrust();

    void selectTable(QModelIndex index);

    void slotTableMenuRequested( QPoint pos );
    void deleteTableMenu();
    void viewCertTableMenu();
    void decodeCertTableMenu();

    void slotTreeMenuRequested( QPoint pos );
    void viewCertTreeMenu();
    void decodeCertTreeMenu();

private:
    void initialize();
    int verifyURL( const QString strHost, int nPort );
    void createTree( const BINList *pCertList );
    long getFlags();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    void* ssl_pctx_;
};

#endif // TLS_VERIFY_DLG_H
