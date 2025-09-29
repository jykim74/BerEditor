/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CSR_INFO_DLG_H
#define CSR_INFO_DLG_H

#include <QDialog>
#include "ui_csr_info_dlg.h"
#include "js_bin.h"
#include "js_pki_x509.h"

namespace Ui {
class CSRInfoDlg;
}

class CSRInfoDlg : public QDialog, public Ui::CSRInfoDlg
{
    Q_OBJECT

public:
    explicit CSRInfoDlg(QWidget *parent = nullptr);
    ~CSRInfoDlg();

    int setReqPath( const QString strPath );
    void setReqBIN( const BIN *pReq, const QString strTitle = "" );

    static QTableWidgetItem* getExtNameItem( const QString strSN );

private slots:
    void showEvent(QShowEvent *event);
    void clickField(QModelIndex index);

    void clickExport();
    void clickViewPubKey();

    void clickVerifyCSR();
    void clickDecodeCSR();

private:
    void setTitle( const QString strName );
    void initUI();
    void initialize();
    int saveAsPEM( const BIN *pData );

    void resetData();

    QString req_path_;
    BIN req_bin_;
    JReqInfo req_info_;
    JExtensionInfoList* ext_info_list_;
};

#endif // CSR_INFO_DLG_H
