/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SSS_DLG_H
#define SSS_DLG_H

#include <QDialog>
#include "ui_sss_dlg.h"

namespace Ui {
class SSSDlg;
}

class SSSDlg : public QDialog, public Ui::SSSDlg
{
    Q_OBJECT

public:
    explicit SSSDlg(QWidget *parent = nullptr);
    ~SSSDlg();

private slots:
    void srcChanged();
    void joinedChanged();
    void clickAdd();
    void clickSplit();
    void clickJoin();
    void clickMakePrime();

    void changePrime( const QString& text );
    void changeShare( const QString& text );

    void slotShareList(QPoint pos);
    void delShare();

    void clearShareTable();
    void clickClearDataAll();
    void clearSrc();
    void clearPrime();
    void clearJoined();

private:
    void initialize();
};

#endif // SSS_DLG_H
