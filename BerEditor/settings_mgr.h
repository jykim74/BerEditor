#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT
private:

public:
    SettingsMgr(QObject *parent = nullptr);

    void setShowPartOnly( bool val );
    bool showPartOnly();

    void setOIDConfigPath( const QString& strPath );
    QString OIDConfigPath();

    void setShowLogTab( bool bVal );
    bool showLogTab();
signals:

public slots:
private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
