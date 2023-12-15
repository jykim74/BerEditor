#ifndef SSL_VERIFY_DLG_H
#define SSL_VERIFY_DLG_H

#include <QDialog>
#include "ui_ssl_verify_dlg.h"
#include "js_bin.h"


namespace Ui {
class SSLVerifyDlg;
}

class SSLVerifyDlg : public QDialog, public Ui::SSLVerifyDlg
{
    Q_OBJECT

public:
    explicit SSLVerifyDlg(QWidget *parent = nullptr);
    ~SSLVerifyDlg();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

private slots:
    void clickConnect();
    void clickRefresh();
    void clickClearURL();
    void clickClearSaveURL();
    void clickClearResult();

    void findTrustCACert();
    void clickClearTrust();
    void clickAddCipher();
    void checkFixCipherName();
    void checkHostName();
    void clickClearCipher();

    void selectTable(QModelIndex index);

    void slotTableMenuRequested( QPoint pos );
    void deleteTableMenu();
    void viewCertTableMenu();
    void decodeCertTableMenu();

    void slotTreeMenuRequested( QPoint pos );
    void viewCertTreeMenu();
    void decodeCertTreeMenu();
    void saveTrustedCA();

private:
    void initialize();
    int verifyURL( const QString strHost, int nPort );
    void createTree( const BINList *pCertList );
    long getFlags();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // SSL_VERIFY_DLG_H
