#ifndef BER_APPLET_H
#define BER_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;

class SettingsMgr;

class MainWindow;

class BerApplet : public QObject
{
    Q_OBJECT
public:
    BerApplet(QObject *parent = nullptr);
    ~BerApplet();

    void start();

    MainWindow* mainWindow() { return main_win_; };
    SettingsMgr *settingsMgr() { return settings_mgr_; };

    QString cmd() { return cmd_; };
    void log( const QString strLog, QColor cr = QColor(00,00,00) );

    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    bool closingDown() { return in_exit_ || about_to_quit_; };

    void restartApp();
    void setCmd( const QString cmd );
    QString getSetPath();

signals:

public slots:

private:
    Q_DISABLE_COPY(BerApplet)

    MainWindow* main_win_;

    SettingsMgr* settings_mgr_;


    bool started_;
    bool in_exit_;
    bool about_to_quit_;

    QString cmd_;
};

extern BerApplet *berApplet;

#define STR(s)          #s
#define STRINGIZE(x)    STR(x)

#endif // BER_APPLET_H
