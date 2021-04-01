#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QWidget>
#include "js_bin.h"

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_URL
};

enum {
    ENC_ENCRYPT,
    ENC_DECRYPT
};

enum {
    SIGN_SIGNATURE,
    SIGN_VERIFY
};

enum { JS_FILE_TYPE_CERT, JS_FILE_TYPE_PRIKEY, JS_FILE_TYPE_TXT, JS_FILE_TYPE_BER, JS_FILE_TYPE_CFG };

QString findFile( QWidget *parent, int nType, const QString strPath );
int setOIDList( const QString& strOIDPath );
QString getHexString( const QString& strVal );
QString getHexString( unsigned char *pData, int nDataLen );
QString getHexView( const char *pName, const BIN *pBin );
int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );

#endif // COMMON_H
