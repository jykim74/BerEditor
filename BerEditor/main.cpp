#include "mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "ber_applet.h"
#include "i18n_helper.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"

void setQss( QApplication* app )
{
    QString strStyle;
    QFile qss(":/bereditor.qss");
    qss.open( QFile::ReadOnly );

    strStyle = qss.readAll();

#if defined( Q_OS_WIN32 )
    QFile css( ":/qt-win.css" );
#elif defined( Q_OS_MAC)
    QFile css( ":/qt-mac.css" );
#endif
    css.open( QFile::ReadOnly );

    if( css.size() > 0 )
    {
        strStyle += "\n";
        strStyle += css.readAll();
    }

    app->setStyleSheet( strStyle );
}


int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(bereditor);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "BerEditor" );

#if 0
    QFile qss(":/bereditor.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());
#else
    setQss( &app );
#endif

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName());
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "The file to open" );
    parser.process(app);

//    app.setFont( QFont( "Courier New" ));

    qDebug( "command : %s\n", argv[0] );
    I18NHelper::getInstance()->init();

    BerApplet mApplet;
    mApplet.setCmd( argv[0] );
    berApplet = &mApplet;
    berApplet->start();

    QFont font;
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
