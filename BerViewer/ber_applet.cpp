#include "mainwindow.h"
#include "ber_applet.h"

BerApplet *berApplet;

BerApplet::BerApplet(QObject *parent) : QObject(parent)
{
    main_win_ = new MainWindow;
}

BerApplet::~BerApplet()
{
    delete main_win_;
}

void BerApplet::start()
{
    main_win_->show();
}
