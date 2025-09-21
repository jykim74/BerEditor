/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef KEY_MAN_DLG_H
#define KEY_MAN_DLG_H

#include <QDialog>
#include "ui_key_man_dlg.h"

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
    void clickKEMEncap();
    void clickKEMDecap();

    void changeKEMKey();
    void changeKEMWrappedKey();
    void changeKEMDecKey();
private:
    void initialize();
};

#endif // KEY_MAN_DLG_H
