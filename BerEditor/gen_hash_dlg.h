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
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void digest();
    int hashInit();
    void hashUpdate();
    void hashFinal();
    void clearInput();
    void clearOutput();
    void inputChanged();
    void outputChanged();

    void changeOutputHash();

    void clickClearDataAll();

    void clickFindSrcFile();
    void clickDigest();
    void clickDigestSrcFile();

    void clickDigestSrcFileThread();

    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );

private:
    void initUI();
    void initialize();
    void appendStatusLabel( const QString& strLabel );
    void updateStatusLabel();

    void setSrcFileInfo( const QString strFile );

    int update_cnt_;
    void *pctx_;
    HashThread *thread_;
};

#endif // GEN_HASH_DLG_H
