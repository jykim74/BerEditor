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

    void clickInputClear();
    void clickOutputClear();

    void clickPriKeyView();
    void clickPriKeyDecode();
    void clickCertView();
    void clickCertDecode();

    void clickPriKeyType();
    void clickCertType();

    void clickFindSrcFile();
    void changeInputTab( int index );

    void fileRunThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( int nUpdate );

    void checkCertGroup();

public slots:
    void checkEncPriKey();
    void checkUseKeyAlg();
    void clickSign();
    void clickVerify();
    void clickClearDataAll();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    int readPrivateKey( BIN *pPriKey );

    int getPrivateKey( BIN *pPriKey, int *pnType );
    int getPublicKey( BIN *pPubKey, int *pnType );

    int hsmSignInit();
    int hsmSignUpdate();
    int hsmSignFinal( BIN *pSign );
    int hsmSign( BIN *pSign );
    long getP11Mech();

    void *sctx_;

    int update_cnt_;
    SignVerifyThread *thread_;
    bool is_hsm_;
};

#endif // SIGN_VERIFY_DLG_H
