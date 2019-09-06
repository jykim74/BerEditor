#ifndef AUTO_UPDATE_SERVICE_H
#define AUTO_UPDATE_SERVICE_H

#include <QObject>

class AutoUpdateService : public QObject
{
    Q_OBJECT
public:
    explicit AutoUpdateService(QObject *parent = nullptr);

signals:

public slots:
};

#endif // AUTO_UPDATE_SERVICE_H
