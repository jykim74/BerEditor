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
    kCmdSignedData, kCmdEnvelopedData, kCmdAddSigned, kCmdData, kCmdDigest
};

const QStringList kDecodeList = {
    kCmdVerifyData, kCmdDevelopedData, kCmdGetData, kCmdGetDigest
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
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void checkEncode();
    void checkDecode();
    void checkAutoDetect();

    void clickClose();
    void clickOutputDecode();
    void clickPriFind();
    void clickCertFind();

    void clickSignedData();
    void clickEnvelopedData();
    void clickVerifyData();
    void clickDevelopedData();
    void clickAddSigner();
    void clickData();
    void clickDigest();
    void clickGetData();
    void clickGetDigest();

    void clickPriKeyView();
    void clickPriKeyDecode();
    void clickCertView();
    void clickCertDecode();

    void clickPriKeyType();
    void clickCertType();

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
    void clickExport();

    void checkEncPriKey();

    void clickOutputUp();

    void changeCmd();
    void clickRun();

private:
    void initUI();
    void initialize();
    int readPrivateKey( BIN *pPriKey );
    int getFlags();
};

#endif // CMS_DLG_H
