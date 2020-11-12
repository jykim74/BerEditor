#include <QString>
#include <QFileDialog>

#include "common.h"

QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

//    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BIN )
        strType = QObject::tr("Binary Files (*.bin *.der);;All Files(*.*)");

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};
