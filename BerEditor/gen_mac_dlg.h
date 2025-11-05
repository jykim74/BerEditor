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
#include "js_bin.h"

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
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void mac();

    int macInit();
    void macUpdate();
    void macFinal();

    void clickReset();

    void inputClear();
    void outputClear();

    void inputChanged();
    void outputChanged();
    void keyChanged();
    void ivChanged();

    void checkGenerate();
    void checkVerify();
    void changeMethod();

    void clickClearDataAll();
    void clickMAC();
    void clickFindSrcFile();
    void clickMACSrcFile();

    void clickMacSrcFileThread();
    void startTask();
    void onTaskFinished();
    void onTaskUpdate( qint64 nUpdate );
private:
    void freeCTX();

    void initUI();
    void initialize();

    int verifyMAC( const BIN *pMAC, const BIN *pInMAC );
    void setSrcFileInfo( const QString strFile );

    void *hctx_;
    int type_;

    MacThread *thread_;
};

#endif // GEN_MAC_DLG_H
