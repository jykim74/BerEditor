/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef BER_TRAY_ICON_H
#define BER_TRAY_ICON_H

#include <QSystemTrayIcon>

class BerTrayIcon : public QSystemTrayIcon
{
    Q_OBJECT

public:
    BerTrayIcon();
};

#endif // BER_TRAY_ICON_H
