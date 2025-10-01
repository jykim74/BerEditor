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
    void fileRunThread();

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

    void checkEncrypt();
    void checkDecrypt();


    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );

private:
    void initUI();
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void updateStatusLabel();

    bool isCCM( const QString strAlg );
    void *ctx_;
    int update_cnt_;
    EncDecThread *thread_;
};

#endif // ENC_DEC_DLG_H
