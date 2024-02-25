/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef AUTO_UPDATE_SERVICE_H
#define AUTO_UPDATE_SERVICE_H

#include <QObject>
#include "singleton.h"



class AutoUpdateAdapter;

class AutoUpdateService : public QObject
{
    SINGLETON_DEFINE(AutoUpdateService)
    Q_OBJECT
public:
    AutoUpdateService(QObject *parent = nullptr);

    bool shouldSupportAutoUpdate() const;
    void setRequestParams();
    bool autoUpdateEnabled() const;
    void setAutoUpdateEnabled(bool enabled);

    void start();
    void stop();

    void checkUpdate();

private:
    void enableUpdateByDefault();
    QString getAppcastURI();
    AutoUpdateAdapter *adapter_;
};

#endif // AUTO_UPDATE_SERVICE_H
