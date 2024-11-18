/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef BER_APPLET_H
#define BER_APPLET_H

#include <QObject>
#include <QMessageBox>
#include "js_bin.h"
#include "js_license.h"

class MainWindow;
class SettingsMgr;
class CAVPDlg;

class BerApplet : public QObject
{
    Q_OBJECT
public:
    BerApplet(QObject *parent = nullptr);
    ~BerApplet();

    void start();
    int checkLicense();
    JS_LICENSE_INFO& LicenseInfo() { return license_info_; };

    MainWindow* mainWindow() { return main_win_; };
    SettingsMgr *settingsMgr() { return settings_mgr_; };
    void decodeData( const BIN *pData, const QString strPath );
    void decodeTTLV( const BIN *pData );

    const BIN& getBER();
    const BIN& getTTLV();


    QString cmd() { return cmd_; };
    void log( const QString strLog, QColor cr = QColor(00,00,00) );
    void logLine();
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(00,00,00) );
    void line( QColor cr = QColor(00,00,00) );
    void line2( QColor cr = QColor(00,00,00) );

    void messageBox(const QString& msg, QWidget *parent);
    void warningBox(const QString& msg, QWidget *parent);
    bool yesOrNoBox(const QString& msg, QWidget *parent, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    void messageLog( const QString strLog, QWidget *parent );
    void warnLog( const QString strLog, QWidget *parent );


    static QString getBrand();

    void restartApp();
    void exitApp( int nNum = 0 );
    void setCmd( const QString cmd );

    QString getBERPath();
    void setBERPath( const QString strPath );

    bool isPRO() { return is_pro_; };
    bool isLicense() { return is_license_; };

    QString curFilePath( const QString strPath = "" );
    QString curPath( const QString strPath = "" );

signals:

public slots:

private:
    Q_DISABLE_COPY(BerApplet)

    MainWindow* main_win_;
    SettingsMgr* settings_mgr_;

    bool is_pro_;
    bool is_license_;
    JS_LICENSE_INFO license_info_;

    QString cmd_;
    QString cur_file_;
};

extern BerApplet *berApplet;

#define STR(s)          #s
#define STRINGIZE(x)    STR(x)

#endif // BER_APPLET_H
