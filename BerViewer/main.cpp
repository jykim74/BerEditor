#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "ber_applet.h"
#include "i18n_helper.h"


int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(berviewer);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "BerViewer" );

    QFile qss(":/berviewer.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());

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

/*
    MainWindow mw;
    if( !parser.positionalArguments().isEmpty() )
        mw.loadFile( parser.positionalArguments().first() );

    mw.show();
*/
    return app.exec();
}
