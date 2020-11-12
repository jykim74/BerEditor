#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QWidget>

enum { JS_FILE_TYPE_CERT, JS_FILE_TYPE_PRIKEY, JS_FILE_TYPE_TXT, JS_FILE_TYPE_BIN };

QString findFile( QWidget *parent, int nType, const QString strPath );

#endif // COMMON_H
