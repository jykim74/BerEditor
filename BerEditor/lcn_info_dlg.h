/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef LCN_INFO_DLG_H
#define LCN_INFO_DLG_H

#include <QDialog>
#include "ui_lcn_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class LCNInfoDlg;
}

class LCNInfoDlg : public QDialog, public Ui::LCNInfoDlg
{
    Q_OBJECT

public:
    explicit LCNInfoDlg(QWidget *parent = nullptr);
    ~LCNInfoDlg();
    void setCurTab( int index );
    const QString getSID() { return SID_; };

private slots:
    void clickGet();
    void clickUpdate();
    void clickRemove();
    void checkUseFile();
    void checkStopMessage();

private:
    QString getLicenseURI();
    void initialize();
    int getLCN( const QString& strEmail, const QString& strKey, BIN *pLCN );
    int updateLCN( const QString strEmail, const QString strKey, BIN *pLCN );
    void settingsLCN( const QString strSID, const BIN *pLCN );

    QString SID_;
};

#endif // LCN_INFO_DLG_H
