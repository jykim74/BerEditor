/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CRL_INFO_DLG_H
#define CRL_INFO_DLG_H

#include <QDialog>
#include "ui_crl_info_dlg.h"
#include "js_bin.h"
#include "js_pki_x509.h"

namespace Ui {
class CRLInfoDlg;
}

class CRLInfoDlg : public QDialog, public Ui::CRLInfoDlg
{
    Q_OBJECT

public:
    explicit CRLInfoDlg(QWidget *parent = nullptr);
    ~CRLInfoDlg();

    int setCRLPath( const QString strPath );
    QTableWidgetItem* getExtNameItem( const QString strSN );

    void setCRL_BIN( const BIN *pCRL );

private slots:
    void clickCRLField( QModelIndex index );
    void clickRevokeField( QModelIndex index );
    void showEvent(QShowEvent *event);

    void clickSave();
    void clickSaveToMan();
    void clickDecodeCRL();
    void clickVerifyCRL();

private:

    void initialize();
    void initUI();
    void clearTable();
    int saveAsPEM( const BIN *pData );
    void resetData();

    QString crl_path_;
    BIN     crl_bin_;
    JCRLInfo crl_info_;
    JExtensionInfoList* ext_info_list_;
    JRevokeInfoList* revoke_info_list_;
};

#endif // CRL_INFO_DLG_H
