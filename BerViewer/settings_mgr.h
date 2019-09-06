#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT
public:
    explicit SettingsMgr(QObject *parent = nullptr);

signals:

public slots:
};

#endif // SETTINGS_MGR_H
