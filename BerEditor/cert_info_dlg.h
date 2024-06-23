/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_INFO_DLG_H
#define CERT_INFO_DLG_H

#include <QDialog>
#include "ui_cert_info_dlg.h"
#include "js_bin.h"
#include "js_pki_x509.h"


namespace Ui {
class CertInfoDlg;
}

class CertInfoDlg : public QDialog, public Ui::CertInfoDlg
{
    Q_OBJECT

public:
    explicit CertInfoDlg(QWidget *parent = nullptr);
    ~CertInfoDlg();

    int setCertPath( const QString strPath );
    void setCertBIN( const BIN *pCert );

    QTableWidgetItem* getExtNameItem( const QString strSN );

    static const QString getCRL_URIFromExt( const QString strExtCRLDP );
    static const QString getOCSP_URIFromExt( const QString strExtAIA );
    static const QString getCA_URIFromExt( const QString strExtAIA );
    static bool isCA( const QString strExtBC );
    static int getCA( const QString strExtAIA, BIN *pCA );
    static int getCRL( const QString strExtCRLDP, BIN *pCRL );
    static const QString getValueFromExtList( const QString strExtName, JExtensionInfoList *pExtList );

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );
    void changeFieldType( int index );
    void clickSave();
    void clickSaveCA();
    void clickSaveTrustedCA();

    void clickMakeTree();
    void clickGetCA();
    void clickGetCRL();
    void clickDecodeCert();
    void clickPathValidation();
    void clickVerifyCert();
    void clickOCSPCheck();
    void clickCRLCheck();

    void clickTreeItem(QTreeWidgetItem* item, int index);

private:

    int saveAsPEM( const BIN *pData );
    const QString getValueFromExtList( const QString strExtName );

    void getFields();
    void initUI();
    void clearTable();

    void resetData();

    QString cert_path_;
    BIN cert_bin_;
    JCertInfo cert_info_;
    JExtensionInfoList* ext_info_list_;
    int self_sign_;
    BINList* path_list_;
};

#endif // CERT_INFO_DLG_H
