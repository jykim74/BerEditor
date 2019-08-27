#ifndef BER_APPLET_H
#define BER_APPLET_H

#include <QObject>

class BerApplet : public QObject
{
    Q_OBJECT
public:
    explicit BerApplet(QObject *parent = nullptr);

signals:

public slots:
};

#endif // BER_APPLET_H
