/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QFileInfo>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "ber_applet.h"
#include "i18n_helper.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"

int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(bereditor);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "BerEditor" );

    QGuiApplication::setWindowIcon(QIcon(":/images/bereditor.png"));

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName());
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "The file to open" );
    parser.process(app);

    qDebug( "command : %s\n", argv[0] );
    I18NHelper::getInstance()->init();

    BerApplet mApplet;
    mApplet.setCmd( argv[0] );
    berApplet = &mApplet;
    berApplet->start();

    static QFont font;



    QString strFont = berApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    app.setFont(font);

    MainWindow *mw = berApplet->mainWindow();
    if( !parser.positionalArguments().isEmpty() )
    {
        mw->loadFile( parser.positionalArguments().first() );
        mw->show();
    }

    return app.exec();
}
