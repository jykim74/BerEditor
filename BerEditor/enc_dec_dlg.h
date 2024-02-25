/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef ENC_DEC_DLG_H
#define ENC_DEC_DLG_H

#include <QDialog>
#include "ui_enc_dec_dlg.h"

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
    void clickUseAE();
    int encDecInit();
    void encDecUpdate();
    void encDecFinal();
    void dataChange();

    void inputChanged();
    void outputChanged();
    void keyChanged();
    void ivChanged();
    void aadChanged();
    void tagChanged();
    void modeChanged();

    void changeMethod( int index );
    void clickClearDataAll();

    void clickInputClear();
    void clickOutputClear();

    void clickFindSrcFile();
    void clickFindDstFile();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    bool isCCM( const QString strAlg );
    void *ctx_;
};

#endif // ENC_DEC_DLG_H
