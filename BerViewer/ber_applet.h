#ifndef BER_APPLET_H
#define BER_APPLET_H

#include <QObject>

class MainWindow;

class BerApplet : public QObject
{
    Q_OBJECT
public:
    BerApplet(QObject *parent = nullptr);
    ~BerApplet();

    void start();

signals:

public slots:

private:
    Q_DISABLE_COPY(BerApplet)

    MainWindow* main_win_;
};

extern BerApplet *berApplet;

#endif // BER_APPLET_H
