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
    void clickEditMode();
    void checkACalc();
    void checkBCalc();
    void clickRun();

    void calcualteA();
    void calcualteB();
    void PClear();
    void secretClear();
    void genDHParam();
    void exportDHParam();
    void importDHParam();
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
    void getAFromCertMan();
    void getAFromKeyPair();

    void genBECDHPriKey();
    void genBECDHPubKey();
    void findBECDHPriKey();
    void getBFromCertMan();
    void getBFromKeyPair();

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
    void initUI();
    void initialize();

    void setEnableAPriKey( bool bVal );
    void setEnableAPubKey( bool bVal );
    void setEnableAECDHPriKey( bool bVal );
    void setEnableAECDHPubKey( bool bVal );

    void setEnableBPriKey( bool bVal );
    void setEnableBPubKey( bool bVal );
    void setEnableBECDHPriKey( bool bVal );
    void setEnableBECDHPubKey( bool bVal );
};

#endif // KEY_AGREE_DLG_H
