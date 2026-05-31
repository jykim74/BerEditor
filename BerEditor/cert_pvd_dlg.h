/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_PVD_DLG_H
#define CERT_PVD_DLG_H

#include <QDialog>
#include "ui_cert_pvd_dlg.h"
#include "js_bin.h"

namespace Ui {
class CertPVDDlg;
}

enum {
    PVD_CERT = 0,
    PVD_TRUST,
    PVD_UNTRUST,
    PVD_CRL,
    PVD_OCSP
};

class CertPVDDlg : public QDialog, public Ui::CertPVDDlg
{
    Q_OBJECT

public:
    explicit CertPVDDlg(QWidget *parent = nullptr);
    ~CertPVDDlg();
    void setTarget( const QString strPath );
    void setTarget( const BIN *pTarget );

    void setPathList( const BINList *pCAList, const BINList *pCRLList );

    static int getStatusData( const BIN *pCert, bool bOnline, BIN *pCA, BIN *pCRL, BIN *pOCSP );
    static int getStatusDataList( const BIN *pCert, bool bOnline, BINList **ppCAList, BINList **ppCRLList, BINList **ppOCSPList );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void slotPathMenu( QPoint pos );
    void slotPathTreeMenu( QPoint pos );
    void slotParamMenu( QPoint pos );

    void viewData();
    void viewTreeData();

    void delPath();
    void sendTarget();
    void sendTreePath();
    void sendTreeAllPath();
    void delParam();

    void clickTrustFind();
    void clickUntrustFind();
    void clickCRLFind();
    void clickTargetFind();

    void checkUseTrustList();
    void clickTrustList();

    void clickTrustInfo();
    void clickUntrustInfo();
    void clickCRLInfo();
    void clickTargetInfo();

    void clickTrustAdd();
    void clickUntrustAdd();
    void clickCRLAdd();

    void clickListClear();
    void clickPathClear();
    void clickMakePath();

    void checkATTime();

    void clickParamAdd();
    void clickParamListClear();

    void clickVerifyCert();
    void clickVerifyCRL();
    void clickPolicyCheck();
    void clickPathValidation();

    void clickTrustDecode();
    void clickUntrustDecode();
    void clickCRLDecode();
    void clickTargetDecode();
    void clickTargetList();

    void clickClearDataAll();

private:
    void initUI();
    void initialize();
    void addList( const QString strType, const QString strPath );
    void addList( const QString strType, const BIN *pData );

    BIN target_;
};

#endif // CERT_PVD_DLG_H
