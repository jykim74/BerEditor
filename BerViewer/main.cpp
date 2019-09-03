#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "ber_applet.h"


int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(berviewer);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JPKIProject" );
    QCoreApplication::setApplicationName( "PKI BerViewer" );
    QCoreApplication::setApplicationVersion( QT_VERSION_STR );

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName());
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "The file to open" );
    parser.process(app);

    BerApplet mApplet;
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
