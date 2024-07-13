/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef RSA_ENC_DEC_DLG_H
#define RSA_ENC_DEC_DLG_H

#include <QDialog>
#include "ui_pub_enc_dec_dlg.h"
#include "js_bin.h"

namespace Ui {
class PubEncDecDlg;
}

class PubEncDecDlg : public QDialog, public Ui::PubEncDecDlg
{
    Q_OBJECT

public:
    explicit PubEncDecDlg(QWidget *parent = nullptr);
    ~PubEncDecDlg();

private slots:
    void Run();
    void checkPubKeyEncrypt();
    void checkAutoCertOrPubKey();
    void clickCheckKeyPair();
    void findCert();
    void findPrivateKey();
    void changeValue();

    void inputChanged();
    void outputChanged();
    void algChanged();

    void clickPriKeyView();
    void clickPriKeyDecode();
    void clickCertView();
    void clickCertDecode();

    void clickPriKeyType();
    void clickCertType();

    void checkUseKeyAlg();
    void clickClearDataAll();
    void checkEncPriKey();

    void changeOtherPub();
    void changeIV( const QString& text );
    void changeTag( const QString& text );

    void clickInputClear();
    void clickOutputClear();

private:
    void initialize();
    int readPrivateKey( BIN *pPriKey );
    QString last_path_;

};

#endif // RSA_ENC_DEC_DLG_H
