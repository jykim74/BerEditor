/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef KEY_AGREE_DLG_H
#define KEY_AGREE_DLG_H

#include <QDialog>
#include "ui_key_agree_dlg.h"

namespace Ui {
class KeyAgreeDlg;
}

class KeyAgreeDlg : public QDialog, public Ui::KeyAgreeDlg
{
    Q_OBJECT

public:
    explicit KeyAgreeDlg(QWidget *parent = nullptr);
    ~KeyAgreeDlg();

private slots:
    void calcualteA();
    void calcualteB();
    void secretClear();
    void genDHParam();
    void genADHPri();
    void genBDHPri();
    void genADHKey();
    void genBDHKey();
    void genAKeyPair();
    void genBKeyPair();
    void checkAPubKey();
    void checkBPubKey();
    void checkAKeyPair();
    void checkBKeyPair();

    void genAECDHPriKey();
    void genAECDHPubKey();
    void findAECDHPriKey();
    void genBECDHPriKey();
    void genBECDHPubKey();
    void findBECDHPriKey();

    void pChanged();

    void APriKeyChanged();
    void APubKeyChanged();
    void BPriKeyChanged();
    void BPubKeyChanged();

    void AECDHPriKeyChanged();
    void AECDHPubKeyChanged();
    void BECDHPriKeyChanged();
    void BECDHPubKeyChanged();

    void secretKeyChanged();
    void clickClearDataAll();

    void changeECDHParam( int index );

private:
    void initialize();
};

#endif // KEY_AGREE_DLG_H
