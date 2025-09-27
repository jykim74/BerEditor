/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef KEY_MAN_DLG_H
#define KEY_MAN_DLG_H

#include <QDialog>
#include "ui_key_man_dlg.h"
#include "js_bin.h"

namespace Ui {
class KeyManDlg;
}

class KeyManDlg : public QDialog, public Ui::KeyManDlg
{
    Q_OBJECT

public:
    explicit KeyManDlg(QWidget *parent = nullptr);
    ~KeyManDlg();

private slots:
    void clickClearDataAll();

    void clickKD_DeriveKey();

    void changeKD_Secret();
    void changeKD_Salt();
    void changeKD_Info();
    void changeKD_Output();

    void checkKD_PBKDF();
    void checkKD_HKDF();
    void checkKD_X963();
    void checkKD_Scrypt();

    void clickKD_SaltClear();
    void clickKD_OutputClear();

    void runKW_Wrap();
    void runKW_Unwrap();

    void checkKW_KeyWrap();
    void checkKW_KeyUnwrap();

    void clickKW_Run();
    void clickKW_Change();

    void clickKW_SrcClear();
    void clickKW_KEKClear();
    void clickKW_DstClear();

    void clickKW_GenKEK();

    void chageKW_Src();
    void chageKW_Dst();
    void changeKW_KEK();

    void runKEMEncap();
    void runKEMDecap();

    void clickKEMRun();

    void checkKEMPriKeyEncrypted();

    void changeKEMKey();
    void changeKEMWrappedKey();

    void clickKEMWrappedKeyClear();
    void clickKEMKeyClear();

    void clickKEMPriKeyFind();
    void clickKEMPriKeyView();
    void clickKEMPriKeyDecode();
    void clickKEMPriKeyType();

    void clickKEMCertFind();
    void clickKEMCertView();
    void clickKEMCertDecode();
    void clickKEMCertType();

    void checkKEMEncap();
    void checkKEMDecap();
private:
    void initUI();
    void initialize();

    int readKEMPrivateKey( BIN *pPriKey );
    int getKEMPrivateKey( BIN *pPriKey );
    int getKEMPublicKey( BIN *pPubKey );

    void setKEMEnableWrappedKey( bool bVal );
    void setKEMEnableKey( bool bVal );
    void setKEMEnableCert( bool bVal );
    void setKEMEnablePriKey( bool bVal );
};

#endif // KEY_MAN_DLG_H
