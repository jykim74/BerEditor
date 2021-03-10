#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "ber_applet.h"
#include "i18n_helper.h"


int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(bereditor);

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "BerEditor" );

    QFile qss(":/bereditor.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());

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

/*
    MainWindow mw;
    if( !parser.positionalArguments().isEmpty() )
        mw.loadFile( parser.positionalArguments().first() );

    mw.show();
*/
#ifdef Q_OS_WIN32
    QFont font;
    font.setFamily(QString("굴림체"));
    app.setFont(font);
#endif

    return app.exec();
}
