/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CMS_DLG_H
#define CMS_DLG_H

#include <QDialog>
#include "ui_cms_dlg.h"
#include "js_bin.h"

namespace Ui {
class CMSDlg;
}

class CMSDlg : public QDialog, public Ui::CMSDlg
{
    Q_OBJECT

public:
    explicit CMSDlg(QWidget *parent = nullptr);
    ~CMSDlg();

private slots:
    void clickClose();
    void clickCMSDecode();
    void clickSignPriFind();
    void clickSignCertFind();
    void clickKMPriFind();
    void clickKMCertFind();

    void clickSignedData();
    void clickEnvelopedData();
    void clickSignAndEnvloped();
    void clickVerifyData();
    void clickDevelopedData();
    void clickDevelopedAndVerify();

    void clickAddSigner();

    void clickSignPriKeyView();
    void clickSignPriKeyDecode();
    void clickSignCertView();
    void clickSignCertDecode();

    void clickKMPriKeyView();
    void clickKMPriKeyDecode();
    void clickKMCertView();
    void clickKMCertDecode();

    void clickSignPriKeyType();
    void clickSignCertType();
    void clickKMPriKeyType();
    void clickKMCertType();

    void srcChanged();
    void CMSChanged();

    void clearSrc();
    void clearCMS();

    void clickCMSView();
    void clickClearDataAll();
    void clickReadFile();

    void checkSignEncPriKey();
    void checkKMEncPriKey();

private:
    void initialize();
    int readSignPrivateKey( BIN *pPriKey );
    int readKMPrivateKey( BIN *pPriKey );

    QButtonGroup* group_;

};

#endif // CMS_DLG_H
