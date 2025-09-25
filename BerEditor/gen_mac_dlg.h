/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GEN_MAC_DLG_H
#define GEN_MAC_DLG_H

#include <QDialog>
#include <QButtonGroup>
#include "ui_gen_mac_dlg.h"

#define JS_TYPE_HMAC    0
#define JS_TYPE_CMAC    1
#define JS_TYPE_GMAC    2

class MacThread;

namespace Ui {
class GenMacDlg;
}

class GenMacDlg : public QDialog, public Ui::GenMacDlg
{
    Q_OBJECT

public:
    explicit GenMacDlg(QWidget *parent = nullptr);
    ~GenMacDlg();

private slots:
        void mac();
        int macInit();
        void macUpdate();
        void macFinal();

        void inputClear();
        void outputClear();

        void inputChanged();
        void outputChanged();
        void keyChanged();
        void ivChanged();

        void checkHMAC();
        void checkCMAC();
        void checkGMAC();

        void clickClearDataAll();
        void clickMAC();
        void clickFindSrcFile();
        void clickMACSrcFile();

        void clickMacSrcFileThread();
        void startTask();
        void onTaskFinished();
        void onTaskUpdate( int nUpdate );
private:
        void freeCTX();

        void initUI();
        void initialize();
        void appendStatusLabel( const QString strLabel );
        void updateStatusLabel();

        void *hctx_;
        int type_;
        int update_cnt_;
        QButtonGroup* group_;
        MacThread *thread_;
};

#endif // GEN_MAC_DLG_H
