/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SETTINGS_DLG_H
#define SETTINGS_DLG_H

#include <QDialog>

#include "ui_settings_dlg.h"

namespace Ui {
class SettingsDlg;
}

class SettingsDlg : public QDialog, public Ui::SettingsDlg
{
    Q_OBJECT

public:
    SettingsDlg(QWidget *parent = nullptr);
    ~SettingsDlg();

private slots:
    void updateSettings();
    void onOkBtnClicked();
    void onCancelBtnClicked();
    void findOIDConfig();
    void findCertPath();
    void findHsmPath();
    void closeEvent(QCloseEvent *event );
    void showEvent(QShowEvent *event);



private:
    void initialize();
    void initFontFamily();
//    Ui::SettingsDlg *ui;
    Q_DISABLE_COPY(SettingsDlg);
};

#endif // SETTINGS_DLG_H
