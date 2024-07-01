/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SIGN_VERIFY_DLG_H
#define SIGN_VERIFY_DLG_H

#include <QDialog>
#include "ui_sign_verify_dlg.h"
#include "js_bin.h"

class SignVerifyThread;

namespace Ui {
class SignVerifyDlg;
}

class SignVerifyDlg : public QDialog, public Ui::SignVerifyDlg
{
    Q_OBJECT

public:
    explicit SignVerifyDlg(QWidget *parent = nullptr);
    ~SignVerifyDlg();

private slots:
    void checkPubKeyVerify();
    void checkAutoCertOrPubKey();
    void clickCheckKeyPair();
    void findPrivateKey();
    void findCert();
    void algChanged(int index);
    void Run();

    void dataRun();
    void fileRun();

    void digestRun();

    int signVerifyInit();
    void signVerifyUpdate();
    void signVerifyFinal();

    void inputChanged();
    void outputChanged();
    void changeMethod( int index );

    void clickInputClear();
    void clickOutputClear();

    void clickPriKeyDecode();
    void clickCertView();
    void clickCertDecode();

    void clickPriKeyType();
    void clickCertType();

    void checkUseKeyAlg();
    void clickClearDataAll();
    void clickFindSrcFile();

    void changeInputTab( int index );
    void checkEncPriKey();

    void fileRunThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( int nUpdate );
private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    int readPrivateKey( BIN *pPriKey );
    void *sctx_;
    void *hctx_;
    bool is_eddsa_;
    QString last_path_;

    int update_cnt_;
    SignVerifyThread *thread_;
};

#endif // SIGN_VERIFY_DLG_H
