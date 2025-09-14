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

const QString kCmdData = "Data";
const QString kCmdDigest = "Digest";
const QString kCmdSignedData = "Signed";
const QString kCmdEnvelopedData = "Enveloped";
const QString kCmdSignedAndEnveloped = "SignedAndEnveloped";
const QString kCmdAddSigned = "Add Signed";
const QString kCmdGetData = "GetData";
const QString kCmdGetDigest = "GetDigest";
const QString kCmdVerifyData = "Verify";
const QString kCmdDevelopedData = "Developed";
const QString kCmdDevelopedAndVerify = "DevelopedAndVerify";

const QStringList kEncodeList = {
    kCmdData, kCmdDigest, kCmdSignedData, kCmdEnvelopedData, kCmdSignedAndEnveloped, kCmdAddSigned
};

const QStringList kDecodeList = {
    kCmdGetData, kCmdGetDigest, kCmdVerifyData, kCmdDevelopedData, kCmdDevelopedAndVerify
};

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

    void clickData();
    void clickDigest();
    void clickGetData();
    void clickGetDigest();

    void clickCMSUp();

    void changeType();
    void changeCmd();
    void clickRun();

private:
    void initUI();
    void initialize();
    int readSignPrivateKey( BIN *pPriKey );
    int readKMPrivateKey( BIN *pPriKey );
};

#endif // CMS_DLG_H
