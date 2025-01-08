/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SSL_CHECK_DLG_H
#define SSL_CHECK_DLG_H

#include <QDialog>
#include "ui_ssl_check_dlg.h"
#include "js_bin.h"


namespace Ui {
class SSLCheckDlg;
}

class SSLCheckDlg : public QDialog, public Ui::SSLCheckDlg
{
    Q_OBJECT

public:
    explicit SSLCheckDlg(QWidget *parent = nullptr);
    ~SSLCheckDlg();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

private slots:
    void clickCheck();
    void clickRefresh();
    void clickClearURL();
    void clickClearSaveURL();
    void clickClearResult();
    void clickClearLog();

    void clickAddCipher();
    void checkFixCipherName();
    void clickClearCipher();
    void clickViewTrustList();

    void selectTable(QModelIndex index);

    void slotTableMenuRequested( QPoint pos );
    void verifyTableMenu();
    void deleteTableMenu();
    void viewCertTableMenu();
    void decodeCertTableMenu();

    void slotTreeMenuRequested( QPoint pos );
    void viewCertTreeMenu();
    void decodeCertTreeMenu();
    void saveTrustedCA();

    void checkUseMutual();

    void findTrustCACert();
    void clickTrustCAView();
    void clickTrustCADecode();
    void clickTrustCAType();

    void findClientCA();
    void clickClientCAView();
    void clickClientCADecode();
    void clickClientCAType();

    void findClientCert();
    void clickClientCertView();
    void clickClientCertDecode();
    void clickClientCertType();

    void findClientPriKey();
    void clickClientPriKeyView();
    void clickClientPriKeyDecode();
    void clickClientPriKeyType();

private:
    void initialize();
    int verifyURL( const QString strHost, int nPort, BIN *pCA = NULL );
    const QTreeWidgetItem* createTree( const QString strHost, int nPort, const BINList *pCertList, bool bGood );
    long getFlags();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );
    void checkRootAndTrust( const BIN *pCA, const QString strHost, int nPort );

    int removeExistURL( const QString strHost, int nPort );
    QTreeWidgetItem* url_tree_root_;
};

#endif // SSL_CHECK_DLG_H
