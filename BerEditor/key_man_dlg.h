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
    void clickMakeKey();
    void secretChanged();
    void saltChanged();
    void infoChanged();
    void keyValueChanged();

    void clickWrap();
    void clickUnwrap();
    void clickClear();
    void clickChange();

    void checkPBKDF();
    void checkHKDF();
    void checkX963();
    void checkScrypt();

    void clickOutputClear();

    void clickKeyWrapGenKEK();

    void srcChanged();
    void dstChanged();
    void kekChanged();
    void clickClearDataAll();

    void clickKEMClearAll();
    void runKEMEncap();
    void runKEMDecap();

    void clickKEMRun();

    void checkKEMPriKeyEncrypted();

    void changeKEMKey();
    void changeKEMWrappedKey();
    void changeKEMDecKey();

    void clickKEMWrappedKeyClear();
    void clickKEMKeyClear();
    void clickKEMDecKeyClear();

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
    void setKEMEnableDecKey( bool bVal );
    void setKEMEnableCert( bool bVal );
    void setKEMEnablePriKey( bool bVal );
};

#endif // KEY_MAN_DLG_H
