/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_HASH_DLG_H
#define GEN_HASH_DLG_H

#include <QDialog>
#include "ui_gen_hash_dlg.h"

class HashThread;

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

    void clickDigestSrcFileThread();

    void startTask();
    void onTaskFinished();
    void onTaskUpdate( int nUpdate );

private:
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void updateStatusLabel();

    int update_cnt_;
    void *pctx_;
    HashThread *thread_;
};

#endif // GEN_HASH_DLG_H
