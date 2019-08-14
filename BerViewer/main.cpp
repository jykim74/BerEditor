#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>


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


    MainWindow mw;
    if( !parser.positionalArguments().isEmpty() )
        mw.loadFile( parser.positionalArguments().first() );

    mw.show();

    return app.exec();
}
