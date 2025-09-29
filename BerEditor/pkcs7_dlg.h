/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CMS_DLG_H
#define CMS_DLG_H

#include <QDialog>
#include "ui_pkcs7_dlg.h"
#include "js_bin.h"

const QString kCmdData = "Data";
const QString kCmdDigest = "Digest";
const QString kCmdSignedData = "Signed";
const QString kCmdEnvelopedData = "Enveloped";
const QString kCmdSignedAndEnveloped = "Signed and Enveloped";
const QString kCmdAddSigned = "Add Signed";
const QString kCmdGetData = "GetData";
const QString kCmdGetDigest = "GetDigest";
const QString kCmdVerifyData = "Verify";
const QString kCmdDevelopedData = "Developed";
const QString kCmdDevelopedAndVerify = "Developed and Verify";

const QStringList kEncodeList = {
    kCmdSignedData, kCmdEnvelopedData, kCmdSignedAndEnveloped, kCmdAddSigned, kCmdData, kCmdDigest
};

const QStringList kDecodeList = {
    kCmdVerifyData, kCmdDevelopedData, kCmdDevelopedAndVerify, kCmdGetData, kCmdGetDigest
};

namespace Ui {
class PKCS7Dlg;
}

class PKCS7Dlg : public QDialog, public Ui::PKCS7Dlg
{
    Q_OBJECT

public:
    explicit PKCS7Dlg(QWidget *parent = nullptr);
    ~PKCS7Dlg();

private slots:
    void checkEncode();
    void checkDecode();
    void checkAutoDetect();

    void clickClose();
    void clickOutputDecode();
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
    void clickData();
    void clickDigest();
    void clickGetData();
    void clickGetDigest();

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
    void outputChanged();

    void clearSrc();
    void clearOutput();

    void clickSrcView();
    void clickSrcDecode();
    void clickSrcType();
    void clickOutputType();
    void clickOutputView();
    void clickClearDataAll();
    void clickReadFile();
    void clickWriteFile();

    void checkSignEncPriKey();
    void checkKMEncPriKey();



    void clickOutputUp();

    void changeCmd();
    void clickRun();

private:
    void initUI();
    void initialize();
    int readSignPrivateKey( BIN *pPriKey );
    int readKMPrivateKey( BIN *pPriKey );
};

#endif // CMS_DLG_H
