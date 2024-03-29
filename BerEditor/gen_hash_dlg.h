/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_HASH_DLG_H
#define GEN_HASH_DLG_H

#include <QDialog>
#include "ui_gen_hash_dlg.h"

namespace Ui {
class GenHashDlg;
}

class GenHashDlg : public QDialog, public Ui::GenHashDlg
{
    Q_OBJECT

public:
    GenHashDlg(QWidget *parent = nullptr);
    ~GenHashDlg();

private slots:
    void digest();
    int hashInit();
    void hashUpdate();
    void hashFinal();
    void clearInput();
    void clearOutput();
    void inputChanged();
    void outputChanged();

    void clickClearDataAll();

    void clickFindSrcFile();
    void clickDigest();
    void clickDigestSrcFile();

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );

    void *pctx_;
//    Ui::GenHashDlg *ui;
};

#endif // GEN_HASH_DLG_H
