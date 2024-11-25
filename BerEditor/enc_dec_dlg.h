/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef ENC_DEC_DLG_H
#define ENC_DEC_DLG_H

#include <QDialog>
#include "ui_enc_dec_dlg.h"

class EncDecThread;

namespace Ui {
class EncDecDlg;
}

class EncDecDlg : public QDialog, public Ui::EncDecDlg
{
    Q_OBJECT

public:
    explicit EncDecDlg(QWidget *parent = nullptr);
    ~EncDecDlg();

private slots:
    void showEvent(QShowEvent *event );
    void Run();
    void dataRun();
    void fileRun();
    void clickUseAEAD();
    int encDecInit();
    int encDecUpdate();
    int encDecFinal();
    void dataChange();

    void inputChanged();
    void outputChanged();
    void keyChanged();
    void ivChanged();
    void aadChanged();
    void tagChanged();
    void modeChanged();

    void clickClearDataAll();

    void clickInputClear();
    void clickOutputClear();

    void clickFindSrcFile();
    void clickFindDstFile();

    void clickEncrypt();
    void clickDecrypt();

    void fileRunThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( int nUpdate );

private:
    int hsmEncDecInit();
    int hsmEncDecUpdate();
    int hsmEncDecFinal();
    int hsmEncDec();

    void initialize();
    void appendStatusLabel( const QString& strLabel );
    bool isCCM( const QString strAlg );
    long getP11EncMech();

    void *ctx_;
    int update_cnt_;
    EncDecThread *thread_;
    bool is_hsm_;
};

#endif // ENC_DEC_DLG_H
